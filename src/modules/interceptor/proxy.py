from mitmproxy import ctx
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
import asyncio
import threading

class InterceptorProxy:
    def __init__(self):
        self.is_running = False
        self.master = None
        self.thread = None
    
    def start(self, port=8080):
        if self.is_running:
            return
        
        opts = options.Options(listen_host='127.0.0.1', listen_port=port)
        opts.add_option("body_size_limit", int, 0, "")
        
        self.master = DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        
        self.thread = threading.Thread(
            target=self.run_proxy_thread,
            daemon=True
        )
        self.is_running = True
        self.thread.start()
    
    def run_proxy_thread(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            self.master.run()
        except Exception as e:
            print(f"Proxy error: {e}")
        finally:
            self.is_running = False
    
    def stop(self):
        if not self.is_running:
            return
        
        self.master.shutdown()
        self.thread.join(timeout=2)
        self.is_running = False
        self.master = None
        self.thread = None 