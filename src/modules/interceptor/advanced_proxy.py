from mitmproxy import ctx
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.script import concurrent
import asyncio
import threading
import json
import re
from typing import Dict, List, Optional, Callable
from pathlib import Path
import jwt
import base64

class AdvancedProxy:
    def __init__(self):
        self.is_running = False
        self.master = None
        self.thread = None
        self.tokens: Dict[str, List[Dict]] = {}
        self.modifications: List[Dict] = []
        self.replay_queue: List[Dict] = []
        self._stop_event = threading.Event()
    
    def start(self, port: int = 8080):
        """Start the advanced proxy server."""
        if self.is_running:
            return
        
        opts = options.Options(listen_host='127.0.0.1', listen_port=port)
        opts.add_option("body_size_limit", int, 0, "")
        
        self.master = DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        
        # Add custom addons
        self.master.addons.add(TokenExtractor(self))
        self.master.addons.add(RequestModifier(self))
        self.master.addons.add(ReplayHandler(self))
        
        self.thread = threading.Thread(
            target=self.run_proxy_thread,
            daemon=True
        )
        self.is_running = True
        self.thread.start()
    
    def run_proxy_thread(self):
        """Run the proxy server in a separate thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            self.master.run()
        except Exception as e:
            print(f"Proxy error: {e}")
        finally:
            self.is_running = False
    
    def stop(self):
        """Stop the proxy server."""
        if not self.is_running:
            return
        
        self._stop_event.set()
        self.master.shutdown()
        self.thread.join(timeout=2)
        self.is_running = False
        self.master = None
        self.thread = None
    
    def add_modification(self, pattern: str, replacement: str, headers: bool = True):
        """Add a request/response modification rule."""
        self.modifications.append({
            'pattern': pattern,
            'replacement': replacement,
            'headers': headers
        })
    
    def clear_modifications(self):
        """Clear all modification rules."""
        self.modifications.clear()
    
    def add_to_replay_queue(self, request: Dict):
        """Add a request to the replay queue."""
        self.replay_queue.append(request)
    
    def clear_replay_queue(self):
        """Clear the replay queue."""
        self.replay_queue.clear()
    
    def get_tokens(self) -> Dict[str, List[Dict]]:
        """Get all extracted tokens."""
        return self.tokens.copy()
    
    def clear_tokens(self):
        """Clear all extracted tokens."""
        self.tokens.clear()

class TokenExtractor:
    def __init__(self, proxy: AdvancedProxy):
        self.proxy = proxy
        self.token_patterns = {
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'api_key': r'[a-zA-Z0-9_-]{32,}',
            'bearer': r'Bearer\s+([a-zA-Z0-9_-]+)',
            'session': r'session[=:]\s*([a-zA-Z0-9_-]+)'
        }
    
    def request(self, flow):
        """Extract tokens from requests."""
        self._extract_tokens(flow.request)
    
    def response(self, flow):
        """Extract tokens from responses."""
        self._extract_tokens(flow.response)
    
    def _extract_tokens(self, message):
        """Extract tokens from a message using regex patterns."""
        if not message:
            return
        
        # Check headers
        for header, value in message.headers.items():
            self._check_for_tokens(header, value)
        
        # Check body
        if message.content:
            try:
                body = message.content.decode('utf-8')
                self._check_for_tokens('body', body)
            except:
                pass
    
    def _check_for_tokens(self, source: str, content: str):
        """Check content for tokens using regex patterns."""
        for token_type, pattern in self.token_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                token = match.group(0)
                if token_type not in self.proxy.tokens:
                    self.proxy.tokens[token_type] = []
                
                self.proxy.tokens[token_type].append({
                    'token': token,
                    'source': source,
                    'content': content[:100] + '...' if len(content) > 100 else content
                })

class RequestModifier:
    def __init__(self, proxy: AdvancedProxy):
        self.proxy = proxy
    
    def request(self, flow):
        """Modify requests based on rules."""
        self._apply_modifications(flow.request)
    
    def response(self, flow):
        """Modify responses based on rules."""
        self._apply_modifications(flow.response)
    
    def _apply_modifications(self, message):
        """Apply modification rules to a message."""
        if not message:
            return
        
        for mod in self.proxy.modifications:
            if mod['headers']:
                # Modify headers
                for header, value in message.headers.items():
                    if re.search(mod['pattern'], value):
                        message.headers[header] = re.sub(
                            mod['pattern'],
                            mod['replacement'],
                            value
                        )
            
            # Modify body
            if message.content:
                try:
                    body = message.content.decode('utf-8')
                    if re.search(mod['pattern'], body):
                        message.content = re.sub(
                            mod['pattern'],
                            mod['replacement'],
                            body
                        ).encode('utf-8')
                except:
                    pass

class ReplayHandler:
    def __init__(self, proxy: AdvancedProxy):
        self.proxy = proxy
    
    def request(self, flow):
        """Handle request replay."""
        if not self.proxy.replay_queue:
            return
        
        # Get the next request from the queue
        replay_request = self.proxy.replay_queue.pop(0)
        
        # Modify the current request based on the replay request
        flow.request.method = replay_request.get('method', flow.request.method)
        flow.request.url = replay_request.get('url', flow.request.url)
        
        # Update headers
        for header, value in replay_request.get('headers', {}).items():
            flow.request.headers[header] = value
        
        # Update body if present
        if 'body' in replay_request:
            flow.request.content = replay_request['body'].encode('utf-8') 