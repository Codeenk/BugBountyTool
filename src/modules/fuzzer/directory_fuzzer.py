import aiohttp
import asyncio
import threading
from typing import List, Dict, Optional, Callable
from urllib.parse import urljoin
import time

class DirectoryFuzzer:
    def __init__(self):
        self.is_running = False
        self.results: List[Dict] = []
        self._stop_event = threading.Event()
    
    async def _test_path(self, session: aiohttp.ClientSession, base_url: str, path: str) -> Optional[Dict]:
        """Test a single path and return result if found."""
        url = urljoin(base_url, path)
        try:
            async with session.get(url) as response:
                if response.status != 404:  # Consider any non-404 response as interesting
                    return {
                        'url': url,
                        'status': response.status,
                        'content_length': len(await response.text()),
                        'content_type': response.headers.get('content-type', '')
                    }
        except Exception:
            pass
        return None
    
    async def _fuzzer_worker(self, base_url: str, wordlist: List[str]):
        """Worker to perform the fuzzing."""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for path in wordlist:
                if self._stop_event.is_set():
                    break
                
                # Create task for each path
                task = asyncio.create_task(self._test_path(session, base_url, path))
                tasks.append(task)
                
                # Process in batches of 10 to avoid overwhelming the server
                if len(tasks) >= 10:
                    for completed in asyncio.as_completed(tasks):
                        result = await completed
                        if result:
                            self.results.append(result)
                    tasks = []
                
                # Small delay to be nice to the server
                await asyncio.sleep(0.1)
            
            # Process any remaining tasks
            if tasks:
                for completed in asyncio.as_completed(tasks):
                    result = await completed
                    if result:
                        self.results.append(result)
    
    def fuzz(self,
             target_url: str,
             wordlist: List[str],
             callback: Optional[Callable] = None) -> None:
        """
        Start directory fuzzing process.
        
        Args:
            target_url: Base URL to fuzz
            wordlist: List of paths to test
            callback: Function to call with results when fuzzing completes
        """
        if self.is_running:
            return
        
        def fuzzing_thread():
            try:
                self.is_running = True
                self.results.clear()
                self._stop_event.clear()
                
                # Create and run event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._fuzzer_worker(target_url, wordlist))
                
                if callback:
                    callback(self.results)
            except Exception as e:
                print(f"Fuzzing error: {e}")
            finally:
                self.is_running = False
        
        thread = threading.Thread(target=fuzzing_thread)
        thread.daemon = True
        thread.start()
    
    def get_results(self) -> List[Dict]:
        """Get the current fuzzing results."""
        return self.results.copy()
    
    def stop(self) -> None:
        """Stop the current fuzzing process if one is running."""
        self._stop_event.set()
        self.is_running = False 