import os
import sys
import logging
from pathlib import Path
import json
import requests
from PySide6.QtCore import QObject, Signal, QThread

# Current version of the application
APP_VERSION = "1.0.0"
# Base URL for updates
UPDATE_URL = "https://example.com/updates"  # Replace with your actual update server

class UpdateWorker(QThread):
    """Worker thread for checking and applying updates."""
    update_available = Signal(str)
    update_progress = Signal(int)
    update_complete = Signal(bool, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.logger = logging.getLogger("UpdateWorker")
    
    def run(self):
        """Check for updates and download if available."""
        try:
            # Check for updates
            latest_version, download_url = self._check_for_updates()
            
            if latest_version and self._is_newer_version(latest_version):
                # Signal that an update is available
                self.update_available.emit(latest_version)
                
                # Download the update
                success, message = self._download_update(download_url)
                self.update_complete.emit(success, message)
            else:
                self.update_complete.emit(False, "No updates available")
        except Exception as e:
            self.logger.error(f"Update error: {str(e)}")
            self.update_complete.emit(False, f"Update error: {str(e)}")
    
    def _check_for_updates(self):
        """Check if updates are available."""
        try:
            response = requests.get(f"{UPDATE_URL}/version.json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get("version"), data.get("download_url")
            return None, None
        except Exception as e:
            self.logger.error(f"Failed to check for updates: {str(e)}")
            return None, None
    
    def _is_newer_version(self, version):
        """Check if the remote version is newer than the current version."""
        current_parts = [int(x) for x in APP_VERSION.split(".")]
        remote_parts = [int(x) for x in version.split(".")]
        
        for i in range(max(len(current_parts), len(remote_parts))):
            current = current_parts[i] if i < len(current_parts) else 0
            remote = remote_parts[i] if i < len(remote_parts) else 0
            
            if remote > current:
                return True
            elif remote < current:
                return False
        
        return False  # Versions are equal
    
    def _download_update(self, url):
        """Download the update package."""
        if not url:
            return False, "No download URL provided"
        
        try:
            # Create updates directory if it doesn't exist
            updates_dir = Path("updates")
            updates_dir.mkdir(exist_ok=True)
            
            # Download the file
            response = requests.get(url, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            
            if response.status_code == 200:
                file_path = updates_dir / "update.exe"
                
                with open(file_path, 'wb') as f:
                    downloaded = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            progress = int((downloaded / total_size) * 100) if total_size > 0 else 0
                            self.update_progress.emit(progress)
                
                return True, str(file_path)
            else:
                return False, f"Download failed with status code: {response.status_code}"
        except Exception as e:
            self.logger.error(f"Download error: {str(e)}")
            return False, f"Download error: {str(e)}"

class Updater(QObject):
    """Handles checking for and applying updates."""
    update_available = Signal(str)
    update_progress = Signal(int)
    update_complete = Signal(bool, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.logger = logging.getLogger("Updater")
    
    def check_for_updates(self):
        """Check if updates are available."""
        if self.worker and self.worker.isRunning():
            return
        
        self.worker = UpdateWorker()
        self.worker.update_available.connect(self.update_available)
        self.worker.update_progress.connect(self.update_progress)
        self.worker.update_complete.connect(self.update_complete)
        self.worker.start()
    
    def apply_update(self, update_path):
        """Apply the downloaded update."""
        try:
            # In a real implementation, you would:
            # 1. Verify the update package (signature, checksum)
            # 2. Extract it to a temporary location
            # 3. Replace the current executable
            # 4. Restart the application
            
            # For now, we'll just simulate the process
            self.logger.info(f"Applying update from {update_path}")
            
            # In a real scenario, you might use something like:
            # import subprocess
            # subprocess.Popen([update_path, "--update", os.getpid()])
            # sys.exit(0)
            
            return True, "Update applied successfully"
        except Exception as e:
            self.logger.error(f"Failed to apply update: {str(e)}")
            return False, f"Failed to apply update: {str(e)}"
    
    @staticmethod
    def get_current_version():
        """Get the current version of the application."""
        return APP_VERSION 