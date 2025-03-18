import json
import html
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
import jinja2
import pdfkit
import subprocess
from jinja2 import Environment, FileSystemLoader
import os

class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True
        )
        
        # Configure wkhtmltopdf path
        self.wkhtmltopdf_path = self._get_wkhtmltopdf_path()
        if self.wkhtmltopdf_path:
            pdfkit.configuration(wkhtmltopdf=self.wkhtmltopdf_path)
    
    def _get_wkhtmltopdf_path(self) -> Optional[str]:
        """Get the path to wkhtmltopdf executable."""
        # Common paths for wkhtmltopdf
        possible_paths = [
            r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe",
            r"C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe",
            "wkhtmltopdf"  # If it's in PATH
        ]
        
        for path in possible_paths:
            try:
                if Path(path).is_file():
                    return str(Path(path))
                # Try running wkhtmltopdf to check if it's in PATH
                elif path == "wkhtmltopdf":
                    subprocess.run([path, "-V"], capture_output=True, check=True)
                    return path
            except:
                continue
        
        return None
    
    def generate_html_report(self, data: Dict, filename: Optional[str] = None) -> str:
        """Generate an HTML report."""
        template = self.env.get_template("report.html")
        html_content = template.render(
            data=data,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        output_path = self.output_dir / filename
        output_path.write_text(html_content)
        return str(output_path)
    
    def generate_pdf_report(self, data: Dict, filename: Optional[str] = None) -> str:
        """Generate a PDF report."""
        if not self.wkhtmltopdf_path:
            raise RuntimeError(
                "wkhtmltopdf not found. Please install it from: "
                "https://wkhtmltopdf.org/downloads.html"
            )
        
        # First generate HTML
        html_path = self.generate_html_report(data)
        
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        output_path = self.output_dir / filename
        
        # Convert HTML to PDF
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None
        }
        
        config = pdfkit.configuration(wkhtmltopdf=self.wkhtmltopdf_path)
        pdfkit.from_file(str(html_path), str(output_path), options=options, configuration=config)
        return str(output_path)
    
    def generate_json_report(self, data: Dict, filename: Optional[str] = None) -> str:
        """Generate a JSON report."""
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = self.output_dir / filename
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        return str(output_path)
    
    def generate_report(self, data: Dict, formats: List[str] = None) -> Dict[str, str]:
        """Generate reports in multiple formats."""
        if formats is None:
            formats = ['html', 'pdf', 'json']
        
        results = {}
        for fmt in formats:
            if fmt == 'html':
                results['html'] = self.generate_html_report(data)
            elif fmt == 'pdf':
                results['pdf'] = self.generate_pdf_report(data)
            elif fmt == 'json':
                results['json'] = self.generate_json_report(data)
        
        return results

class ReportData:
    def __init__(self):
        self.data = {
            'scan_info': {
                'start_time': None,
                'end_time': None,
                'target': None,
                'scope': None
            },
            'findings': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            },
            'vulnerabilities': [],
            'subdomains': [],
            'ports': [],
            'tokens': [],
            'requests': [],
            'responses': [],
            'risk_score': 0,
            'summary': {
                'total_findings': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0
            }
        }
    
    def set_scan_info(self, target: str, scope: str):
        """Set scan information."""
        self.data['scan_info'].update({
            'start_time': datetime.now().isoformat(),
            'target': target,
            'scope': scope
        })
    
    def add_finding(self, severity: str, finding: Dict):
        """Add a finding to the report."""
        if severity in self.data['findings']:
            self.data['findings'][severity].append(finding)
            self.data['summary'][f'{severity}_count'] += 1
            self.data['summary']['total_findings'] += 1
    
    def add_vulnerability(self, vuln: Dict):
        """Add a vulnerability to the report."""
        self.data['vulnerabilities'].append(vuln)
    
    def add_subdomain(self, subdomain: str):
        """Add a subdomain to the report."""
        self.data['subdomains'].append(subdomain)
    
    def add_port(self, port: Dict):
        """Add a port to the report."""
        self.data['ports'].append(port)
    
    def add_token(self, token: Dict):
        """Add a token to the report."""
        self.data['tokens'].append(token)
    
    def add_request(self, request: Dict):
        """Add a request to the report."""
        self.data['requests'].append(request)
    
    def add_response(self, response: Dict):
        """Add a response to the report."""
        self.data['responses'].append(response)
    
    def calculate_risk_score(self):
        """Calculate the overall risk score."""
        weights = {
            'critical': 10,
            'high': 7,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        
        score = 0
        for severity, weight in weights.items():
            count = len(self.data['findings'][severity])
            score += count * weight
        
        self.data['risk_score'] = min(score, 100)  # Cap at 100
    
    def finalize(self):
        """Finalize the report data."""
        self.data['scan_info']['end_time'] = datetime.now().isoformat()
        self.calculate_risk_score()
        return self.data 