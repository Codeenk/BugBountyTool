# Bug Bounty Desktop Application

A comprehensive desktop application for security researchers and bug bounty hunters that combines various security testing and reconnaissance capabilities in a user-friendly interface.

Bug Bounty Tool![image](https://github.com/user-attachments/assets/04bafa08-2ccf-45bc-8d48-0560e4805c97)


## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Security Notice](#security-notice)
- [License](#license)

## Features

### 1. HTTPS Traffic Interception
- Real-time HTTP/HTTPS traffic monitoring
- Request and response modification
- Token extraction (JWT, API keys, Bearer tokens)
- Request replay functionality
- Traffic logging and analysis

### 2. Subdomain Discovery
- DNS-based subdomain enumeration
- Certificate transparency log searching
- Common subdomain brute forcing
- Progress tracking and result visualization
- Export capabilities

### 3. Port Scanning
- Nmap integration for comprehensive port scanning
- Fallback to basic socket scanning
- Service detection and version identification
- Custom port range specification
- Thread-safe operation

### 4. Directory Fuzzing
- Web directory and file discovery
- Custom wordlist support
- Status code tracking
- Response size analysis
- Progress monitoring

### 5. Vulnerability Scanning
- Integration with multiple security tools:
  - Nmap for network vulnerability scanning
  - Nuclei for web vulnerability detection
  - XSStrike for cross-site scripting detection
- Customizable tool selection
- Detailed vulnerability reporting
- Risk scoring system

### 6. Reporting
- Multiple report formats (HTML, PDF, JSON)
- Comprehensive vulnerability details
- Risk scoring and categorization
- Timestamp and scan metadata
- Exportable reports with recommendations

## Prerequisites

- Python 3.8 or higher
- Windows 10/11 or Linux/macOS
- Required external tools:
  - Nmap (for port scanning)
  - Nuclei (for web vulnerability scanning)
  - XSStrike (for XSS testing)
  - wkhtmltopdf (for PDF report generation)

## Installation

### Option 1: Using the Installer (Recommended)

1. Download the latest release from the [Releases](https://github.com/Codeenk/bug-bounty-tool/releases) page
2. Run the installer (`BugBountyTool_Setup.exe`)
3. Follow the installation wizard
4. Launch the application from the desktop shortcut.

(This option is currently unavailable due to security issues, but you can use the app directly through the .exe in releases section...)

### Option 2: Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Codeenk/bug-bounty-tool.git
   cd bug-bounty-tool
   ```

2. Create and activate a virtual environment:
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install external tools:
   - Download and install Nmap from https://nmap.org/download.html
   - Download Nuclei from https://github.com/projectdiscovery/nuclei/releases
   - Clone XSStrike from https://github.com/s0md3v/XSStrike
   - Download wkhtmltopdf from https://wkhtmltopdf.org/downloads.html (this is a external software to generate reports and save them in pdf format)

## Quick Start

1. Launch the application:
   ```bash
   # If using manual installation
   python main.py

   # If using installer
   Double-click the desktop shortcut
   ```

2. Configure your settings:
   - Set up proxy settings if needed
   - Configure tool paths
   - Set up report templates

3. Start scanning:
   - Enter your target
   - Select scanning tools
   - Click "Start Scan"

## Usage Guide

### HTTPS Traffic Interception

1. Go to the "Proxy" tab
2. Configure your proxy settings
3. Start the proxy server
4. Configure your browser to use the proxy
5. Start intercepting traffic

### Subdomain Discovery

1. Navigate to the "Subdomain" tab
2. Enter your target domain
3. Select discovery methods
4. Click "Start Scan"
5. View results in the table

### Port Scanning

1. Go to the "Port Scanner" tab
2. Enter target IP or hostname
3. Configure port range
4. Select scanning method
5. Start the scan

### Directory Fuzzing

1. Open the "Fuzzer" tab
2. Enter target URL
3. Select or upload wordlist
4. Configure fuzzing options
5. Start fuzzing

### Vulnerability Scanning

1. Navigate to the "Vulnerability" tab
2. Enter target
3. Select scanning tools
4. Configure scan options
5. Start the scan

## Troubleshooting

### Common Issues

1. **Missing External Tools**
   - Ensure all required tools are installed
   - Verify tool paths in settings
   - Check tool permissions

2. **Proxy Connection Issues**
   - Verify proxy settings
   - Check firewall rules
   - Ensure certificate is installed

3. **Scan Failures**
   - Check target accessibility
   - Verify network connection
   - Review error logs

4. **Report Generation Issues**
   - Ensure wkhtmltopdf is installed
   - Check file permissions
   - Verify template files

### Getting Help

- Check the [Wiki](https://github.com/Codeenk/bug-bounty-tool/wiki)
- Open an [Issue](https://github.com/Codeenk/bug-bounty-tool/issues)

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

### Development Setup

1. Clone the repository
2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```
4. Run tests:
   ```bash
   pytest
   ```

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for functions
- Add tests for new features

## Security Notice

This tool is intended for authorized security testing and research purposes only. Users must:

- Obtain explicit permission before testing any systems
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Respect privacy and confidentiality

See [SECURITY.md](SECURITY.md) for detailed security guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Nmap](https://nmap.org/) for port scanning capabilities
- [Nuclei](https://github.com/projectdiscovery/nuclei) for vulnerability scanning
- [XSStrike](https://github.com/s0md3v/XSStrike) for XSS testing
- All contributors and users of this tool

## Support

For support, please:
- Check the [documentation](docs/)
- Open an [issue](https://github.com/Codeenk/bug-bounty-tool/issues)
- Contact me at malandkar.sarvesh1@gmail.com 

Here's the demo of some features:

https://github.com/user-attachments/assets/4d7a3aca-442f-4b3a-85ba-4e1579c56b8c

