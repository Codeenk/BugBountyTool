import subprocess
import json
import os
from typing import Dict, List, Optional, Callable
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

class ExternalTools:
    def __init__(self):
        self.tools_dir = Path("tools")
        self.tools_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for each tool
        (self.tools_dir / 'nuclei').mkdir(exist_ok=True)
        (self.tools_dir / 'nmap').mkdir(exist_ok=True)
        (self.tools_dir / 'XSStrike').mkdir(exist_ok=True)
        
        # Keep track of scan directories for cleanup
        self.scan_dirs = []
        self._stop_scan = False
        
        self._init_tools()
    
    def _init_tools(self):
        """Initialize external tools and their paths."""
        self.tools = {
            'nuclei': {
                'path': self.tools_dir / 'nuclei' / 'nuclei.exe',
                'templates': self.tools_dir / 'nuclei-templates',
                'config': self.tools_dir / 'nuclei-config.yaml'
            },
            'nmap': {
                'path': 'nmap',  # Usually installed globally
                'scripts': self.tools_dir / 'nmap' / 'scripts'
            },
            'xsstrike': {
                'path': self.tools_dir / 'XSStrike' / 'XSStrike-master' / 'xsstrike.py'
            }
        }
    
    def cleanup_scan_dirs(self):
        """Clean up old scan directories."""
        import shutil
        for dir_path in self.scan_dirs:
            try:
                if dir_path.exists():
                    shutil.rmtree(dir_path)
            except Exception as e:
                print(f"Error cleaning up directory {dir_path}: {e}")
        self.scan_dirs = []

    def stop_current_scan(self):
        """Signal to stop the current scan."""
        self._stop_scan = True
    
    def run_nuclei(self, target: str, templates: List[str] = None, progress_callback: Optional[Callable] = None) -> Dict:
        """Run Nuclei vulnerability scanner with progress updates."""
        if not self.tools['nuclei']['path'].exists():
            raise FileNotFoundError("Nuclei not found. Please install it first.")
        
        self._stop_scan = False
        cmd = [
            str(self.tools['nuclei']['path']),
            '-u', target,
            '-json',
            '-o', str(self.tools_dir / 'nuclei-results.json')
        ]
        
        if templates:
            cmd.extend(['-t', ','.join(templates)])
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            findings = []
            while True:
                if self._stop_scan:
                    process.terminate()
                    break
                
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    findings.append(output.strip())
                    if progress_callback:
                        progress_callback(len(findings))
            
            if self._stop_scan:
                return {'success': False, 'error': 'Scan stopped by user'}
            
            return {'success': True, 'findings': findings}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_nmap(self, target: str, progress_callback: Optional[Callable] = None) -> Dict:
        """Run Nmap vulnerability scan with NSE scripts."""
        try:
            self._stop_scan = False
            scan_output_dir = self._create_scan_dir('nmap')
            output_file = scan_output_dir / 'scan.xml'
            
            # Use common NSE scripts for vulnerability detection
            cmd = [
                'nmap',
                '-sV',  # Version detection
                '-sC',  # Default scripts
                '--script=vuln,auth,default,discovery,version',  # Vulnerability scripts
                '-oX', str(output_file),  # XML output
                '-T4',  # Aggressive timing
                '--max-retries', '2',
                target
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            output_lines = []
            while True:
                if self._stop_scan:
                    process.terminate()
                    break
                
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    output_lines.append(output.strip())
                    if progress_callback:
                        progress_callback(len(output_lines))
            
            if self._stop_scan:
                return {'success': False, 'error': 'Scan stopped by user'}
            
            # Parse XML output
            if output_file.exists():
                findings = self._parse_nmap_xml(output_file)
                return {'success': True, 'findings': findings}
            
            return {'success': False, 'error': 'No results found'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_xsstrike(self, url: str, progress_callback: Optional[Callable] = None) -> Dict:
        """Run XSStrike with progress updates."""
        try:
            self._stop_scan = False
            xsstrike_path = self.tools['xsstrike']['path']
            if not xsstrike_path.exists():
                return {'success': False, 'error': "XSStrike not found"}
            
            output_file = self._create_scan_dir('xsstrike') / 'results.json'
            
            cmd = [
                'python',
                str(xsstrike_path),
                '--url', url,
                '--output', str(output_file),
                '--json'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            output_lines = []
            while True:
                if self._stop_scan:
                    process.terminate()
                    break
                
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    output_lines.append(output.strip())
                    if progress_callback:
                        progress_callback(len(output_lines))
            
            if self._stop_scan:
                return {'success': False, 'error': 'Scan stopped by user'}
            
            # Try to read JSON results
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        findings = json.load(f)
                    return {'success': True, 'findings': findings}
                except json.JSONDecodeError:
                    pass
            
            # Fall back to parsing output
            return {
                'success': True,
                'findings': self._parse_xsstrike_output('\n'.join(output_lines))
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_amass(self, domain: str) -> Dict:
        """Run Amass for subdomain enumeration."""
        if not self.tools['amass']['path'].exists():
            raise FileNotFoundError("Amass not found. Please install it first.")
        
        cmd = [
            str(self.tools['amass']['path']),
            'enum',
            '-d', domain,
            '-json', str(self.tools_dir / 'amass-results.json')
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            with open(self.tools_dir / 'amass-results.json', 'r') as f:
                findings = json.load(f)
            return {
                'success': True,
                'findings': findings
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _parse_nmap_xml(self, xml_file: Path) -> List[Dict]:
        """Parse Nmap XML output into structured findings."""
        findings = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                ip = host.find('.//address[@addrtype="ipv4"]')
                ip = ip.get('addr') if ip is not None else None
                
                # Get hostname if available
                hostname = host.find('.//hostname')
                hostname = hostname.get('name') if hostname is not None else None
                
                # Process each port
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    # Get service info
                    service = port.find('.//service')
                    if service is not None:
                        service_name = service.get('name', '')
                        product = service.get('product', '')
                        version = service.get('version', '')
                    else:
                        service_name = product = version = ''
                    
                    # Get script output (vulnerabilities)
                    scripts = port.findall('.//script')
                    for script in scripts:
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        
                        if 'VULNERABLE' in output or 'WARNING' in output:
                            severity = 'high' if 'VULNERABLE' in output else 'medium'
                            
                            finding = {
                                'type': 'vulnerability',
                                'tool': 'nmap',
                                'host': ip,
                                'hostname': hostname,
                                'port': port_id,
                                'protocol': protocol,
                                'service': service_name,
                                'product': product,
                                'version': version,
                                'script': script_id,
                                'details': output,
                                'severity': severity
                            }
                            findings.append(finding)
        except ET.ParseError as e:
            print(f"Error parsing Nmap XML: {e}")
        
        return findings
    
    def _parse_xsstrike_output(self, output: str) -> List[Dict]:
        """Parse XSStrike output into structured findings."""
        findings = []
        current_finding = None
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Look for XSS findings
            if 'Payload: ' in line:
                if current_finding:
                    findings.append(current_finding)
                current_finding = {
                    'type': 'xss',
                    'payload': line.split('Payload: ')[1],
                    'context': '',
                    'url': '',
                    'severity': 'high'  # XSS is typically high severity
                }
            elif current_finding:
                if 'URL: ' in line:
                    current_finding['url'] = line.split('URL: ')[1]
                elif 'Context: ' in line:
                    current_finding['context'] = line.split('Context: ')[1]
        
        if current_finding:
            findings.append(current_finding)
        
        return findings
    
    def check_nuclei(self) -> bool:
        """Check if Nuclei is installed and available."""
        try:
            nuclei_path = self.tools['nuclei']['path']
            if not nuclei_path.exists():
                return False
            
            # Try running nuclei -version
            result = subprocess.run([str(nuclei_path), '-version'], 
                                 capture_output=True, 
                                 text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def check_nmap(self) -> bool:
        """Check if Nmap is installed and available."""
        try:
            result = subprocess.run(['nmap', '--version'],
                                 capture_output=True,
                                 text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def check_xsstrike(self) -> bool:
        """Check if XSStrike is installed and available."""
        try:
            xsstrike_path = self.tools['xsstrike']['path']
            if not xsstrike_path.exists():
                print(f"XSStrike not found at {xsstrike_path}")  # Debug logging
                return False
            
            # Try to run XSStrike with --help to verify it works
            result = subprocess.run(['python', str(xsstrike_path), '--help'],
                                 capture_output=True,
                                 text=True)
            success = result.returncode == 0
            print(f"XSStrike check {'successful' if success else 'failed'}")  # Debug logging
            return success
        except Exception as e:
            print(f"XSStrike check error: {e}")  # Debug logging
            return False
    
    def _create_scan_dir(self, tool_name: str) -> Path:
        """Create a unique scan directory for a tool."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        scan_dir = self.tools_dir / tool_name / f'scan_{timestamp}'
        scan_dir.mkdir(parents=True, exist_ok=True)
        self.scan_dirs.append(scan_dir)
        
        # Clean up old scan directories
        if len(self.scan_dirs) > 5:
            old_dirs = self.scan_dirs[:-5]
            for dir_path in old_dirs:
                try:
                    if dir_path.exists():
                        import shutil
                        shutil.rmtree(dir_path)
                except Exception as e:
                    print(f"Error cleaning up directory {dir_path}: {e}")
            self.scan_dirs = self.scan_dirs[-5:]
        
        return scan_dir 