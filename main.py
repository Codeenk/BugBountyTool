import sys
import os
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import Qt
from src.gui.main_window import MainWindow

# Add version information
__version__ = "1.0.0"

def check_for_updates():
    """Check for application updates on startup."""
    try:
        from src.modules.updater.updater import Updater
        updater = Updater()
        
        # We're not actually checking for updates here since this is just a demo
        # In a real application, you would connect signals and handle the update process
        print(f"Current version: {updater.get_current_version()}")
        print("Checking for updates... (disabled in demo)")
        
        return True
    except ImportError:
        print("Updater module not available")
        return False

def ensure_directories():
    """Ensure required directories exist."""
    directories = [
        "tools",
        "tools/nuclei",
        "tools/nmap",
        "tools/XSStrike",
        "reports"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def main():
    # Ensure required directories exist
    ensure_directories()
    
    # Check for updates
    check_for_updates()
    
    # Start the application
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern looking style
    
    # Set application information
    app.setApplicationName("Bug Bounty Tool")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("Security Tools")
    
    # Create and show the main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == '__main__':
    main() 

def display_findings(self, findings):
    self.results_table.clear()  # Clear previous results
    for finding in findings:
        # Assuming you have columns for URL, IP, etc.
        row = [finding.get('url'), finding.get('ip'), finding.get('template')]
        self.results_table.addRow(row)  # Add row to your results table