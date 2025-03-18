import os
import sys
import shutil
import subprocess
from pathlib import Path

def clean_build_dirs():
    """Clean up build directories."""
    print("Cleaning build directories...")
    dirs_to_clean = ['build', 'dist', '__pycache__']
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
    
    # Clean up pycache in subdirectories
    for root, dirs, files in os.walk('.'):
        for d in dirs:
            if d == '__pycache__':
                shutil.rmtree(os.path.join(root, d))

def create_icon():
    """Create an icon file if it doesn't exist."""
    if not os.path.exists('icon.ico'):
        print("Icon file not found. Creating a placeholder...")
        try:
            from PIL import Image, ImageDraw
            
            # Create a simple icon
            img = Image.new('RGB', (256, 256), color=(0, 120, 212))
            draw = ImageDraw.Draw(img)
            draw.rectangle(
                [(50, 50), (206, 206)],
                fill=(255, 255, 255)
            )
            img.save('icon.ico')
        except ImportError:
            print("PIL not installed. Skipping icon creation.")

def ensure_tools_directory():
    """Ensure tools directory exists with required subdirectories."""
    print("Setting up tools directory...")
    tools_dir = Path("tools")
    tools_dir.mkdir(exist_ok=True)
    
    # Create subdirectories for each tool
    (tools_dir / 'nuclei').mkdir(exist_ok=True)
    (tools_dir / 'nmap').mkdir(exist_ok=True)
    (tools_dir / 'XSStrike').mkdir(exist_ok=True)

def build_executable():
    """Build the executable using PyInstaller."""
    print("Building executable with PyInstaller...")
    
    # Check if spec file exists
    if not os.path.exists('bug_bounty.spec'):
        print("Spec file not found. Creating one...")
        subprocess.run([
            'pyinstaller',
            '--name=BugBountyTool',
            '--onefile',
            '--windowed',
            '--icon=icon.ico',
            '--add-data=src/modules/reporting/templates;src/modules/reporting/templates',
            '--add-data=tools;tools',
            'main.py'
        ])
    else:
        # Use existing spec file
        subprocess.run(['pyinstaller', 'bug_bounty.spec'])

def setup_auto_update():
    """Set up PyUpdater for auto-updates."""
    print("Setting up auto-update mechanism...")
    
    # Check if PyUpdater is already initialized
    if not os.path.exists('client_config.py'):
        print("Initializing PyUpdater...")
        subprocess.run(['pyupdater', 'init'])
        
        # Create a basic client config
        with open('client_config.py', 'w') as f:
            f.write("""
CLIENT_CONFIG = {
    'APP_NAME': 'BugBountyTool',
    'COMPANY_NAME': 'Security Tools',
    'HTTP_TIMEOUT': 30,
    'MAX_DOWNLOAD_RETRIES': 3,
    'UPDATE_URLS': ['https://example.com/updates'],
}
""")
    
    # Create update script
    with open('update_client.py', 'w') as f:
        f.write("""
import os
import sys
from pyupdater.client import Client
from client_config import CLIENT_CONFIG

def check_for_updates():
    client = Client(CLIENT_CONFIG)
    app_update = client.update_check(
        CLIENT_CONFIG['APP_NAME'],
        '1.0.0'  # Current version
    )
    
    if app_update:
        print("Update available!")
        app_update.download()
        if app_update.is_downloaded():
            print("Update downloaded. Extracting...")
            app_update.extract_restart()
            # This will restart the app with the new version
    else:
        print("No updates available.")

if __name__ == '__main__':
    check_for_updates()
""")

def create_installer():
    """Create a Windows installer using NSIS (if available)."""
    print("Checking for NSIS to create installer...")
    
    # Check if NSIS is installed
    nsis_path = r"C:\Program Files (x86)\NSIS\makensis.exe"
    if os.path.exists(nsis_path):
        print("Creating installer with NSIS...")
        
        # Create NSIS script
        with open('installer.nsi', 'w') as f:
            f.write("""
!include "MUI2.nsh"

Name "Bug Bounty Tool"
OutFile "BugBountyTool_Setup.exe"
InstallDir "$PROGRAMFILES\\Bug Bounty Tool"
InstallDirRegKey HKCU "Software\\Bug Bounty Tool" ""

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File "dist\\BugBountyTool.exe"
  
  # Create shortcut
  CreateDirectory "$SMPROGRAMS\\Bug Bounty Tool"
  CreateShortcut "$SMPROGRAMS\\Bug Bounty Tool\\Bug Bounty Tool.lnk" "$INSTDIR\\BugBountyTool.exe"
  CreateShortcut "$DESKTOP\\Bug Bounty Tool.lnk" "$INSTDIR\\BugBountyTool.exe"
  
  # Write uninstaller
  WriteUninstaller "$INSTDIR\\Uninstall.exe"
  
  # Registry information for add/remove programs
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Bug Bounty Tool" "DisplayName" "Bug Bounty Tool"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Bug Bounty Tool" "UninstallString" "$\\"$INSTDIR\\Uninstall.exe$\\""
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\\BugBountyTool.exe"
  Delete "$INSTDIR\\Uninstall.exe"
  
  Delete "$SMPROGRAMS\\Bug Bounty Tool\\Bug Bounty Tool.lnk"
  Delete "$DESKTOP\\Bug Bounty Tool.lnk"
  RMDir "$SMPROGRAMS\\Bug Bounty Tool"
  
  RMDir "$INSTDIR"
  
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Bug Bounty Tool"
SectionEnd
""")
        
        # Run NSIS
        subprocess.run([nsis_path, 'installer.nsi'])
        print("Installer created: BugBountyTool_Setup.exe")
    else:
        print("NSIS not found. Skipping installer creation.")
        print("You can download NSIS from https://nsis.sourceforge.io/Download")

def main():
    """Main build process."""
    print("Starting build process for Bug Bounty Tool...")
    
    # Install required packages
    print("Installing required packages...")
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller', 'pyupdater', 'pillow'])
    
    clean_build_dirs()
    create_icon()
    ensure_tools_directory()
    build_executable()
    setup_auto_update()
    create_installer()
    
    print("\nBuild process completed!")
    print("Executable location: dist/BugBountyTool.exe")

if __name__ == "__main__":
    main() 