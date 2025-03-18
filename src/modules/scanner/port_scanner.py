import nmap
import threading
from typing import List, Dict, Optional, Callable
import socket
import concurrent.futures
from queue import Queue
import time

class PortScanner:
    def __init__(self):
        self.is_scanning = threading.Event()
        self.current_scan = None
        self.use_nmap = self._check_nmap_available()
        self._results = []
        self._error = None
        self._lock = threading.Lock()
    
    def _check_nmap_available(self) -> bool:
        """Check if Nmap is available on the system."""
        try:
            self.scanner = nmap.PortScanner()
            return True
        except Exception:
            return False
    
    def _basic_port_scan(self, host: str, port: int) -> Dict:
        """Basic port scan using socket when Nmap is not available."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                state = 'open' if result == 0 else 'closed'
                service = ''
                if state == 'open':
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                return {
                    'number': port,
                    'state': state,
                    'service': service,
                    'version': ''
                }
        except socket.gaierror:
            return {
                'number': port,
                'state': 'error',
                'service': '',
                'version': ''
            }
    
    def scan(self, 
            target: str,
            ports: str = "1-1000",
            arguments: str = "-sV -sS",
            callback: Optional[Callable] = None) -> List[Dict]:
        """
        Start a port scan on the target.
        
        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (e.g. "80,443" or "1-1000")
            arguments: Nmap arguments (only used if Nmap is available)
            callback: Function to call with results when scan completes
            
        Returns:
            List of scan results
        """
        if self.is_scanning.is_set():
            return []
        
        with self._lock:
            self._results = []
            self._error = None
            self.is_scanning.set()
        
        def scan_thread():
            try:
                if self.use_nmap:
                    # Use Nmap if available
                    self.current_scan = self.scanner.scan(
                        target,
                        ports=ports,
                        arguments=arguments
                    )
                    
                    with self._lock:
                        for host in self.scanner.all_hosts():
                            for proto in self.scanner[host].all_protocols():
                                ports_list = self.scanner[host][proto].keys()
                                for port in ports_list:
                                    service = self.scanner[host][proto][port]
                                    self._results.append({
                                        'number': port,
                                        'state': service['state'],
                                        'service': service.get('name', ''),
                                        'version': service.get('version', '')
                                    })
                else:
                    # Use basic socket scanning if Nmap is not available
                    if '-' in ports:
                        start, end = map(int, ports.split('-'))
                        port_list = range(start, end + 1)
                    else:
                        port_list = map(int, ports.split(','))
                    
                    def worker(port):
                        if not self.is_scanning.is_set():
                            return
                        result = self._basic_port_scan(target, port)
                        if result['state'] == 'open':
                            with self._lock:
                                self._results.append(result)
                    
                    # Use ThreadPoolExecutor for parallel scanning
                    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                        futures = [executor.submit(worker, port) for port in port_list]
                        concurrent.futures.wait(
                            futures,
                            timeout=min(len(port_list) * 0.1, 300)  # Max 5 minutes
                        )
                
                if callback and self.is_scanning.is_set():
                    callback(self._results)
            
            except Exception as e:
                with self._lock:
                    self._error = str(e)
                print(f"Scan error: {e}")
            finally:
                self.is_scanning.clear()
        
        # Start scan thread
        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()
        
        # Wait for scan to complete
        thread.join(timeout=300)  # Wait up to 5 minutes
        
        if self._error:
            raise Exception(f"Port scan failed: {self._error}")
        
        return self._results
    
    def stop_scan(self) -> None:
        """Stop the current scan if one is running."""
        if self.is_scanning.is_set():
            if self.use_nmap:
                self.scanner.stop()
            self.is_scanning.clear() 