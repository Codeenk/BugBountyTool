import dns.resolver
import requests
import threading
from typing import List, Set, Optional, Callable
from bs4 import BeautifulSoup
import json
import time
import concurrent.futures
import socket

class SubdomainFinder:
    def __init__(self):
        self.is_running = threading.Event()
        self.subdomains = set()
        self._thread = None
        self._error = None
        self._lock = threading.Lock()
        self._max_workers = 50  # Default value
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def find_subdomains(self,
                       domain: str,
                       use_crt_sh: bool = True,
                       use_dns: bool = True,
                       callback: Optional[Callable] = None,
                       timeout: int = 60,
                       max_workers: int = 50) -> List[dict]:
        """
        Start subdomain discovery process.
        
        Args:
            domain: Target domain to find subdomains for
            use_crt_sh: Whether to use crt.sh certificate transparency logs
            use_dns: Whether to perform DNS enumeration
            callback: Function to call with results when discovery completes
            timeout: Maximum time in seconds to wait for discovery to complete
            max_workers: Maximum number of concurrent workers for DNS resolution
            
        Returns:
            List of discovered subdomains with IP addresses and status
        """
        if self.is_running.is_set():
            return []
        
        with self._lock:
            self._error = None
            self.subdomains.clear()
            self.is_running.set()
            self._max_workers = max_workers
        
        def discovery_thread():
            try:
                if use_crt_sh:
                    self._search_crt_sh(domain)
                
                if use_dns and self.is_running.is_set():
                    self._dns_enumeration(domain)
                
                if callback and self.is_running.is_set():
                    callback(self.get_results())
            except Exception as e:
                with self._lock:
                    self._error = str(e)
                print(f"Discovery error: {e}")
            finally:
                self.is_running.clear()
        
        self._thread = threading.Thread(target=discovery_thread)
        self._thread.daemon = True
        self._thread.start()
        
        # Wait for thread to complete
        self._thread.join(timeout=timeout)  # Wait for specified timeout
        
        if self._error:
            raise Exception(f"Subdomain discovery failed: {self._error}")
        
        return self.get_results()
    
    def _search_crt_sh(self, domain: str) -> None:
        """Search crt.sh for SSL certificates."""
        if not self.is_running.is_set():
            return
            
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self._session.get(url, timeout=30)
            if response.status_code == 200:
                try:
                    data = response.json()
                    with self._lock:
                        for entry in data:
                            name = entry['name_value'].lower()
                            if name.endswith(domain):
                                self.subdomains.add(name)
                except json.JSONDecodeError:
                    print("Error parsing crt.sh JSON response")
        except requests.exceptions.RequestException as e:
            print(f"crt.sh error: {e}")
    
    def _dns_enumeration(self, domain: str) -> None:
        """Perform DNS enumeration using common subdomains."""
        if not self.is_running.is_set():
            return
            
        try:
            # Load subdomains from wordlist file
            wordlist_file = "subdomains-top1mil-5000.txt"
            with open(wordlist_file, 'r') as file:
                common_subdomains = [line.strip() for line in file]
            print(f"Loaded {len(common_subdomains)} subdomains from wordlist")
        except FileNotFoundError:
            # Fallback to a smaller list if file is not found
            print("Wordlist file not found, using default subdomain list")
            common_subdomains = [
                'www', 'mail', 'remote', 'blog', 'webmail', 'server',
                'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
                'staging', 'app', 'test', 'portal', 'admin', 'shop',
                'store', 'blog', 'dev', 'staging', 'prod', 'api',
                'mobile', 'cdn', 'img', 'images', 'static', 'assets',
                'beta', 'alpha', 'demo', 'support', 'help', 'docs',
                'download', 'upload', 'files', 'media', 'search',
                'login', 'signup', 'register', 'account', 'user',
                'admin', 'administrator', 'root', 'system', 'internal',
                'm', 'ftp', 'ssh', 'webdisk', 'mysql', 'db', 'database',
                'git', 'svn', 'jenkins', 'jira', 'confluence', 'proxy',
                'gateway', 'router', 'cloud', 'autodiscover', 'cp'
            ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            def resolve_subdomain(subdomain):
                if not self.is_running.is_set():
                    return
                    
                try:
                    hostname = f"{subdomain}.{domain}"
                    resolver.resolve(hostname, 'A')
                    with self._lock:
                        self.subdomains.add(hostname)
                    print(f"Found subdomain: {hostname}")
                except (dns.resolver.NXDOMAIN,
                       dns.resolver.NoAnswer,
                       dns.resolver.NoNameservers,
                       dns.exception.Timeout):
                    pass
                except Exception as e:
                    print(f"DNS error for {hostname}: {e}")
            
            futures = [executor.submit(resolve_subdomain, subdomain)
                      for subdomain in common_subdomains]
            concurrent.futures.wait(futures, timeout=20)  # Wait up to 20 seconds
    
    def get_results(self) -> List[dict]:
        """Get the current list of discovered subdomains with their IP addresses."""
        results = []
        with self._lock:
            for subdomain in sorted(list(self.subdomains)):
                try:
                    ip = socket.gethostbyname(subdomain)
                    results.append({
                        "name": subdomain,
                        "ip": ip,
                        "status": "Active"
                    })
                except socket.gaierror:
                    # If we can't resolve the IP, it might still be a valid subdomain
                    # but we'll mark it as "Unknown"
                    results.append({
                        "name": subdomain,
                        "ip": "Unknown",
                        "status": "Unknown"
                    })
        return results
    
    def stop(self) -> None:
        """Stop the current discovery process if one is running."""
        self.is_running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2) 