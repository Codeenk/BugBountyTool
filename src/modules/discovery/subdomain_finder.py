import dns.resolver
import requests
import threading
from typing import List, Set, Optional, Callable
from bs4 import BeautifulSoup
import json
import time
import concurrent.futures

class SubdomainFinder:
    def __init__(self):
        self.is_running = threading.Event()
        self.subdomains = set()
        self._thread = None
        self._error = None
        self._lock = threading.Lock()
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def find_subdomains(self,
                       domain: str,
                       use_crt_sh: bool = True,
                       use_dns: bool = True,
                       callback: Optional[Callable] = None) -> List[str]:
        """
        Start subdomain discovery process.
        
        Args:
            domain: Target domain to find subdomains for
            use_crt_sh: Whether to use crt.sh certificate transparency logs
            use_dns: Whether to perform DNS enumeration
            callback: Function to call with results when discovery completes
            
        Returns:
            List of discovered subdomains
        """
        if self.is_running.is_set():
            return []
        
        with self._lock:
            self._error = None
            self.subdomains.clear()
            self.is_running.set()
        
        def discovery_thread():
            try:
                if use_crt_sh:
                    self._search_crt_sh(domain)
                
                if use_dns and self.is_running.is_set():
                    self._dns_enumeration(domain)
                
                if callback and self.is_running.is_set():
                    callback(list(self.subdomains))
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
        self._thread.join(timeout=30)  # Wait up to 30 seconds
        
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
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            def resolve_subdomain(subdomain):
                if not self.is_running.is_set():
                    return
                    
                try:
                    hostname = f"{subdomain}.{domain}"
                    resolver.resolve(hostname, 'A')
                    with self._lock:
                        self.subdomains.add(hostname)
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
    
    def get_results(self) -> List[str]:
        """Get the current list of discovered subdomains."""
        with self._lock:
            return sorted(list(self.subdomains))
    
    def stop(self) -> None:
        """Stop the current discovery process if one is running."""
        self.is_running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2) 