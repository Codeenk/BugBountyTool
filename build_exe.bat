@echo off
echo Building Bug Bounty Tool Executable...

REM Install required packages
echo Installing required packages...
pip install pyinstaller pillow

REM Create tools directory structure
echo Creating tools directory structure...
mkdir tools 2>nul
mkdir tools\nuclei 2>nul
mkdir tools\nmap 2>nul
mkdir tools\XSStrike 2>nul
mkdir reports 2>nul

REM Clean up previous build files
echo Cleaning up previous build files...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del /q BugBountyTool.spec 2>nul

REM Build the executable
echo Building executable with PyInstaller...
pyinstaller --name=BugBountyTool ^
            --onefile ^
            --windowed ^
            --add-data="src/modules/reporting/templates;src/modules/reporting/templates" ^
            --add-data="tools;tools" ^
            --hidden-import=PySide6.QtCore ^
            --hidden-import=PySide6.QtWidgets ^
            --hidden-import=PySide6.QtGui ^
            --hidden-import=mitmproxy ^
            --hidden-import=dns.resolver ^
            --hidden-import=nmap ^
            --hidden-import=jinja2 ^
            --hidden-import=pdfkit ^
            main.py

echo Build complete!
echo Executable location: dist\BugBountyTool.exe

pause 