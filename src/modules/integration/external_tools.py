import subprocess
import json
import os
from typing import Dict, List, Optional, Callable
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
import threading
import logging
from contextlib import contextmanager

class ExternalTools:
    def __init__(self):
        self.tools_dir = Path("tools")
        self.tools_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for each tool
        (self.tools_dir / 'nuclei').mkdir(exist_ok=True)
        (self.tools_dir / 'nmap').mkdir(exist_ok=True)
        (self.tools_dir / 'XSStrike').mkdir(exist_ok=True)
        
        # Thread-safe attributes
        self._lock = threading.Lock()
        self._stop_scan = threading.Event()
        self.scan_dirs = []
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        self._init_tools()
    
    def _init_tools(self):
        """Initialize external tools and their paths."""
        with self._lock:
            self.tools = {
                'nuclei': {
                    'path': self.tools_dir / 'nuclei' / 'nuclei.exe',
                    'templates': self.tools_dir / 'nuclei-templates',
                    'config': self.tools_dir / 'nuclei-config.yaml',
                    'version': None
                },
                'nmap': {
                    'path': 'nmap',  # Usually installed globally
                    'scripts': self.tools_dir / 'nmap' / 'scripts',
                    'version': None
                },
                'xsstrike': {
                    'path': self.tools_dir / 'XSStrike' / 'XSStrike-master' / 'xsstrike.py',
                    'version': None
                }
            }
            
            # Validate tool installations
            self._validate_tools()
    
    def _validate_tools(self):
        """Validate tool installations and get versions."""
        for tool_name, tool_info in self.tools.items():
            try:
                if not self._check_tool_exists(tool_name):
                    self.logger.warning(f"{tool_name} not found or not properly installed")
                    continue
                
                version = self._get_tool_version(tool_name)
                if version:
                    tool_info['version'] = version
                    self.logger.info(f"{tool_name} version: {version}")
            except Exception as e:
                self.logger.error(f"Error validating {tool_name}: {e}")
    
    def _check_tool_exists(self, tool_name: str) -> bool:
        """Check if a tool exists and is executable."""
        tool_info = self.tools.get(tool_name)
        if not tool_info:
            return False
        
        path = tool_info['path']
        if tool_name == 'nmap':
            # Check if Nmap is in PATH
            try:
                subprocess.run(['nmap', '--version'], capture_output=True, check=True)
                return True
            except subprocess.CalledProcessError:
                self.logger.warning("Nmap not found in PATH.")
                return False
        else:
            if not os.path.isfile(path):
                return False
            try:
                subprocess.run(['python', str(path), '--version'], capture_output=True, check=True)
                return True
            except subprocess.CalledProcessError:
                return False
    
    def _get_tool_version(self, tool_name: str) -> Optional[str]:
        """Get the version of an installed tool."""
        try:
            if tool_name == 'nmap':
                result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
                return result.stdout.split('\n')[0]
            elif tool_name == 'nuclei':
                result = subprocess.run([str(self.tools['nuclei']['path']), '-version'], capture_output=True, text=True)
                return result.stdout.strip()
            elif tool_name == 'xsstrike':
                result = subprocess.run(['python', str(self.tools['xsstrike']['path']), '--version'], capture_output=True, text=True)
                return result.stdout.strip()
        except Exception as e:
            self.logger.error(f"Error getting {tool_name} version: {e}")
        return None
    
    @contextmanager
    def _scan_context(self, tool_name: str):
        """Context manager for scan operations."""
        scan_dir = self._create_scan_dir(tool_name)
        try:
            yield scan_dir
        finally:
            self._cleanup_scan_dir(scan_dir)
    
    def _create_scan_dir(self, tool_name: str) -> Path:
        """Create a directory for scan results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = self.tools_dir / f"{tool_name}_scan_{timestamp}"
        scan_dir.mkdir(exist_ok=True)
        
        with self._lock:
            self.scan_dirs.append(scan_dir)
        
        return scan_dir
    
    def _cleanup_scan_dir(self, scan_dir: Path):
        """Clean up a scan directory."""
        try:
            if scan_dir.exists():
                import shutil
                shutil.rmtree(scan_dir)
                with self._lock:
                    if scan_dir in self.scan_dirs:
                        self.scan_dirs.remove(scan_dir)
        except Exception as e:
            self.logger.error(f"Error cleaning up directory {scan_dir}: {e}")
    
    def stop_current_scan(self):
        """Signal to stop the current scan."""
        self._stop_scan.set()
    
    def _reset_scan_state(self):
        """Reset scan state."""
        self._stop_scan.clear()
    
    def run_nuclei(self, target: str, templates: List[str] = None, progress_callback: Optional[Callable] = None) -> Dict:
        """Run Nuclei vulnerability scanner with progress updates."""
        if not self.tools['nuclei']['path'].exists():
            raise FileNotFoundError("Nuclei not found. Please install it first.")
        
        self._reset_scan_state()
        
        with self._scan_context('nuclei') as scan_dir:
            output_file = scan_dir / 'results.jsonl'
            
            cmd = [
                str(self.tools['nuclei']['path']),
                '-u', target,
                '-jsonl',
                '-o', str(output_file)
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
                    if self._stop_scan.is_set():
                        process.terminate()
                        break
                    
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        try:
                            finding = json.loads(output.strip())
                            findings.append(finding)
                            if progress_callback:
                                progress_callback(len(findings))
                        except json.JSONDecodeError:
                            self.logger.warning("Failed to parse Nuclei JSON output")
                
                if self._stop_scan.is_set():
                    return {'success': False, 'error': 'Scan stopped by user'}
                
                return {'success': True, 'findings': findings}
            except Exception as e:
                self.logger.error(f"Error running Nuclei: {e}")
                return {'success': False, 'error': str(e)}
    
    def run_nmap(self, target: str, progress_callback: Optional[Callable] = None) -> Dict:
        """Run Nmap vulnerability scan with NSE scripts."""
        self._reset_scan_state()
        
        with self._scan_context('nmap') as scan_dir:
            output_file = scan_dir / 'scan.xml'
            
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
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1
                )
                
                output_lines = []
                while True:
                    if self._stop_scan.is_set():
                        process.terminate()
                        break
                    
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        output_lines.append(output.strip())
                        if progress_callback:
                            progress_callback(len(output_lines))
                
                if self._stop_scan.is_set():
                    return {'success': False, 'error': 'Scan stopped by user'}
                
                if output_file.exists():
                    findings = self._parse_nmap_xml(output_file)
                    return {'success': True, 'findings': findings}
                
                return {'success': False, 'error': 'No results found'}
            except Exception as e:
                self.logger.error(f"Error running Nmap: {e}")
                return {'success': False, 'error': str(e)}
    
    def run_xsstrike(self, url: str, progress_callback: Optional[Callable] = None) -> Dict:
        """Run XSStrike with progress updates."""
        if not self.tools['xsstrike']['path'].exists():
            raise FileNotFoundError("XSStrike not found. Please install it first.")
        
        self._reset_scan_state()
        
        with self._scan_context('xsstrike') as scan_dir:
            output_file = scan_dir / 'results.json'
            
            cmd = [
                'python',  # Ensure Python is used to run the script
                str(self.tools['xsstrike']['path']),
                '--url', url,
                '--output', str(output_file),
                '--json'
            ]
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1
                )
                
                output_lines = []
                while True:
                    if self._stop_scan.is_set():
                        process.terminate()
                        break
                    
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        output_lines.append(output.strip())
                        if progress_callback:
                            progress_callback(len(output_lines))
                
                if self._stop_scan.is_set():
                    return {'success': False, 'error': 'Scan stopped by user'}
                
                if output_file.exists():
                    try:
                        with open(output_file, 'r') as f:
                            findings = json.load(f)
                        return {'success': True, 'findings': findings}
                    except json.JSONDecodeError:
                        self.logger.warning("Failed to parse XSStrike JSON output")
                
                return {
                    'success': True,
                    'findings': self._parse_xsstrike_output('\n'.join(output_lines))
                }
            except Exception as e:
                self.logger.error(f"Error running XSStrike: {e}")
                return {'success': False, 'error': str(e)}
    
    def _parse_nmap_xml(self, xml_file: Path) -> List[Dict]:
        """Parse Nmap XML output into structured findings."""
        findings = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                host_data = {
                    'ip': host.find('address').get('addr'),
                    'hostname': host.find('hostnames/hostname').get('name') if host.find('hostnames/hostname') is not None else None,
                    'ports': []
                }
                
                for port in host.findall('.//port'):
                    port_data = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('state').get('state'),
                        'service': port.find('service').get('name') if port.find('service') is not None else None,
                        'version': port.find('service').get('product') if port.find('service') is not None else None
                    }
                    host_data['ports'].append(port_data)
                
                findings.append(host_data)
            
            return findings
        except Exception as e:
            self.logger.error(f"Error parsing Nmap XML: {e}")
            return []
    
    def _parse_xsstrike_output(self, output: str) -> List[Dict]:
        """Parse XSStrike output into structured findings."""
        findings = []
        current_finding = {}
        
        for line in output.split('\n'):
            if 'Vulnerable URL:' in line:
                if current_finding:
                    findings.append(current_finding)
                current_finding = {'url': line.split('Vulnerable URL:')[1].strip()}
            elif 'Payload:' in line:
                current_finding['payload'] = line.split('Payload:')[1].strip()
            elif 'Type:' in line:
                current_finding['type'] = line.split('Type:')[1].strip()
        
        if current_finding:
            findings.append(current_finding)
        
        return findings 