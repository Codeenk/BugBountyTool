# Building the Bug Bounty Tool Executable

This document provides instructions for building a standalone executable of the Bug Bounty Tool.

## Prerequisites

1. Python 3.8 or higher
2. pip package manager
3. Windows operating system (for .exe creation)

## Building the Executable

### Option 1: Using the Batch File (Windows)

1. Run the `build_exe.bat` file by double-clicking it or running it from the command prompt:
   ```
   build_exe.bat
   ```

2. The script will:
   - Install required packages (PyInstaller, Pillow)
   - Create necessary directory structure
   - Clean up previous build files
   - Build the executable using PyInstaller

3. Once complete, the executable will be available at `dist\BugBountyTool.exe`

### Option 2: Manual Build

1. Install PyInstaller:
   ```
   pip install pyinstaller
   ```

2. Create the necessary directory structure:
   ```
   mkdir -p tools/nuclei tools/nmap tools/XSStrike reports
   ```

3. Run PyInstaller:
   ```
   pyinstaller --name=BugBountyTool --onefile --windowed --add-data="src/modules/reporting/templates;src/modules/reporting/templates" --add-data="tools;tools" main.py
   ```

4. The executable will be available at `dist\BugBountyTool.exe`

## Running the Executable

Simply double-click the `BugBountyTool.exe` file to run the application. No installation is required.

## External Tool Requirements

The Bug Bounty Tool relies on several external tools for full functionality:

1. **Nmap**: Download from https://nmap.org/download.html and install
2. **Nuclei**: Download from https://github.com/projectdiscovery/nuclei/releases
3. **XSStrike**: Clone from https://github.com/s0md3v/XSStrike

The application will check for these tools and provide instructions if they're missing.

## Troubleshooting

If you encounter issues with the executable:

1. **Missing DLLs**: Ensure you have the Visual C++ Redistributable installed
2. **Antivirus Blocking**: Add an exception for the executable in your antivirus software
3. **Permission Issues**: Run the executable as administrator

## Creating an Installer (Optional)

To create an installer:

1. Download and install NSIS from https://nsis.sourceforge.io/Download
2. Create an NSIS script (installer.nsi) with the appropriate configuration
3. Run the NSIS compiler on the script to generate an installer 