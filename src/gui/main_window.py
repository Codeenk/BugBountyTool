from PySide6.QtWidgets import (QMainWindow, QWidget, QTabWidget,
                             QVBoxLayout, QPushButton, QLabel,
                             QLineEdit, QTextEdit, QSpinBox,
                             QMessageBox, QProgressBar, QHBoxLayout,
                             QComboBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QFileDialog, QGroupBox, QCheckBox)
from PySide6.QtCore import Qt, Slot, QThread, Signal
from PySide6.QtGui import QFont, QIcon
import sys
import os
import logging
from pathlib import Path
import json

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.modules.interceptor.advanced_proxy import AdvancedProxy
from src.modules.scanner.port_scanner import PortScanner
from src.modules.discovery.subdomain_finder import SubdomainFinder
from src.modules.fuzzer.directory_fuzzer import DirectoryFuzzer
from src.modules.database.storage import Storage
from src.modules.integration.external_tools import ExternalTools
from src.modules.reporting.report_generator import ReportGenerator, ReportData

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ScanWorker(QThread):
    progress = Signal(int)
    finished = Signal(dict)
    error = Signal(str)
    status = Signal(str)
    
    def __init__(self, scan_type, target, options=None):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.options = options or {}
        self.tools = ExternalTools()
        self._stop_requested = False
    
    def stop(self):
        """Request the scan to stop."""
        self._stop_requested = True
        if hasattr(self.tools, 'stop_current_scan'):
            self.tools.stop_current_scan()
    
    def run(self):
        try:
            if self._stop_requested:
                return
            
            if self.scan_type == "subdomain":
                self.status.emit("Running subdomain discovery...")
                finder = SubdomainFinder()
                finder.find_subdomains(self.target)
                results = {"subdomains": finder.get_results()}
                self.progress.emit(100)
                self.finished.emit(results)
            
            elif self.scan_type == "port":
                self.status.emit("Running port scan...")
                scanner = PortScanner()
                port_results = []
                def port_callback(scan_results):
                    nonlocal port_results
                    port_results = scan_results
                
                scanner.scan(
                    self.target,
                    ports=f"{self.options.get('start_port', 1)}-{self.options.get('end_port', 1024)}",
                    callback=port_callback
                )
                results = {"ports": port_results}
                self.progress.emit(100)
                self.finished.emit(results)
            
            elif self.scan_type == "directory":
                self.status.emit("Running directory fuzzing...")
                fuzzer = DirectoryFuzzer()
                dir_results = []
                def dir_callback(fuzz_results):
                    nonlocal dir_results
                    dir_results = fuzz_results
                
                fuzzer.fuzz(
                    self.target,
                    wordlist=self.options.get('wordlist', []),
                    callback=dir_callback
                )
                results = {"directories": dir_results}
                self.progress.emit(100)
                self.finished.emit(results)
            
            elif self.scan_type == "vulnerability":
                results = {}
                selected_tool = self.options.get("tools", "All")
                total_tools = 0
                completed_tools = 0
                
                # Determine which tools to run
                run_nuclei = selected_tool in ["All", "Nuclei"]
                run_nmap = selected_tool in ["All", "Nmap"]
                run_xsstrike = selected_tool in ["All", "XSStrike"]
                
                # Count total tools to run
                if run_nuclei: total_tools += 1
                if run_nmap: total_tools += 1
                if run_xsstrike: total_tools += 1
                
                if total_tools == 0:
                    raise Exception("No vulnerability scanning tools selected")
                
                def update_progress(tool_progress):
                    if self._stop_requested:
                        return
                    # Calculate overall progress
                    tool_weight = 100 / total_tools
                    current_tool_progress = (tool_progress / 100) * tool_weight
                    overall_progress = int((completed_tools * tool_weight) + current_tool_progress)
                    self.progress.emit(overall_progress)
                
                # Run Nuclei if selected
                if run_nuclei and not self._stop_requested:
                    self.status.emit("Running Nuclei scan...")
                    results["nuclei"] = self.tools.run_nuclei(
                        self.target,
                        progress_callback=update_progress
                    )
                    if results["nuclei"].get("success"):
                        completed_tools += 1
                    else:
                        logger.error(f"Nuclei scan failed: {results['nuclei'].get('error')}")
                
                # Run Nmap if selected
                if run_nmap and not self._stop_requested:
                    self.status.emit("Running Nmap vulnerability scan...")
                    results["nmap"] = self.tools.run_nmap(
                        self.target,
                        progress_callback=update_progress
                    )
                    if results["nmap"].get("success"):
                        completed_tools += 1
                    else:
                        logger.error(f"Nmap scan failed: {results['nmap'].get('error')}")
                
                # Run XSStrike if selected
                if run_xsstrike and not self._stop_requested:
                    self.status.emit("Running XSStrike scan...")
                    results["xsstrike"] = self.tools.run_xsstrike(
                        self.target,
                        progress_callback=update_progress
                    )
                    if results["xsstrike"].get("success"):
                        completed_tools += 1
                    else:
                        logger.error(f"XSStrike scan failed: {results['xsstrike'].get('error')}")
                
                if self._stop_requested:
                    self.error.emit("Scan stopped by user")
                    return
                
                self.progress.emit(100)
                self.finished.emit({"vulnerabilities": results})
            
            else:
                raise ValueError(f"Unknown scan type: {self.scan_type}")
        
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.error.emit(str(e))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bug Bounty Tool")
        self.setMinimumSize(1200, 800)
        
        # Initialize components
        self.proxy = AdvancedProxy()
        self.storage = Storage()
        self.report_generator = ReportGenerator()
        self.report_data = None
        
        # Initialize scan worker
        self.scan_worker = None
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create tabs
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Add tabs
        tabs.addTab(self.create_proxy_tab(), "Proxy")
        tabs.addTab(self.create_subdomain_tab(), "Subdomain Discovery")
        tabs.addTab(self.create_port_tab(), "Port Scanner")
        tabs.addTab(self.create_fuzzer_tab(), "Directory Fuzzer")
        tabs.addTab(self.create_vulnerability_tab(), "Vulnerability Scanner")
        tabs.addTab(self.create_report_tab(), "Reports")
    
    def create_proxy_tab(self):
        """Create the proxy tab with advanced features."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Proxy controls
        controls = QHBoxLayout()
        
        # Port input
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port:"))
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1024, 65535)
        self.proxy_port.setValue(8080)
        port_layout.addWidget(self.proxy_port)
        controls.addLayout(port_layout)
        
        # SSL/TLS toggle
        self.ssl_toggle = QCheckBox("Enable SSL/TLS")
        self.ssl_toggle.setChecked(True)
        controls.addWidget(self.ssl_toggle)
        
        # Start/Stop buttons
        self.proxy_start_btn = QPushButton("Start Proxy")
        self.proxy_start_btn.clicked.connect(self.start_proxy)
        controls.addWidget(self.proxy_start_btn)
        
        self.proxy_stop_btn = QPushButton("Stop Proxy")
        self.proxy_stop_btn.clicked.connect(self.stop_proxy)
        self.proxy_stop_btn.setEnabled(False)
        controls.addWidget(self.proxy_stop_btn)
        
        layout.addLayout(controls)
        
        # Status and logs
        status_layout = QHBoxLayout()
        self.proxy_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.proxy_status_label)
        self.proxy_log = QTextEdit()
        self.proxy_log.setReadOnly(True)
        self.proxy_log.setMaximumHeight(100)
        layout.addWidget(self.proxy_log)
        
        # Token extraction
        token_group = QGroupBox("Token Extraction")
        token_layout = QVBoxLayout()
        
        # Token patterns
        pattern_layout = QHBoxLayout()
        pattern_layout.addWidget(QLabel("Pattern:"))
        self.token_pattern = QLineEdit()
        pattern_layout.addWidget(self.token_pattern)
        
        self.add_pattern_btn = QPushButton("Add Pattern")
        self.add_pattern_btn.clicked.connect(self.add_token_pattern)
        pattern_layout.addWidget(self.add_pattern_btn)
        
        token_layout.addLayout(pattern_layout)
        
        # Token table
        self.token_table = QTableWidget()
        self.token_table.setColumnCount(3)
        self.token_table.setHorizontalHeaderLabels(["Type", "Token", "Source"])
        self.token_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        token_layout.addWidget(self.token_table)
        
        token_group.setLayout(token_layout)
        layout.addWidget(token_group)
        
        # Request/Response modification
        mod_group = QGroupBox("Request/Response Modification")
        mod_layout = QVBoxLayout()
        
        # Pattern input
        pattern_layout = QHBoxLayout()
        pattern_layout.addWidget(QLabel("Pattern:"))
        self.pattern_input = QLineEdit()
        pattern_layout.addWidget(self.pattern_input)
        
        # Replacement input
        replacement_layout = QHBoxLayout()
        replacement_layout.addWidget(QLabel("Replacement:"))
        self.replacement_input = QLineEdit()
        replacement_layout.addWidget(self.replacement_input)
        
        # Add modification button
        self.add_mod_btn = QPushButton("Add Modification")
        self.add_mod_btn.clicked.connect(self.add_modification)
        
        mod_layout.addLayout(pattern_layout)
        mod_layout.addLayout(replacement_layout)
        mod_layout.addWidget(self.add_mod_btn)
        
        # Modification rules table
        self.mod_table = QTableWidget()
        self.mod_table.setColumnCount(2)
        self.mod_table.setHorizontalHeaderLabels(["Pattern", "Replacement"])
        self.mod_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        mod_layout.addWidget(self.mod_table)
        
        mod_group.setLayout(mod_layout)
        layout.addWidget(mod_group)
        
        # Request replay
        replay_group = QGroupBox("Request Replay")
        replay_layout = QVBoxLayout()
        
        # Request table
        self.replay_table = QTableWidget()
        self.replay_table.setColumnCount(4)
        self.replay_table.setHorizontalHeaderLabels(["Method", "URL", "Headers", "Body"])
        self.replay_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        replay_layout.addWidget(self.replay_table)
        
        # Replay controls
        replay_controls = QHBoxLayout()
        self.replay_btn = QPushButton("Replay Selected")
        self.replay_btn.clicked.connect(self.replay_request)
        replay_controls.addWidget(self.replay_btn)
        
        self.clear_replay_btn = QPushButton("Clear")
        self.clear_replay_btn.clicked.connect(self.clear_replay_table)
        replay_controls.addWidget(self.clear_replay_btn)
        
        replay_layout.addLayout(replay_controls)
        replay_group.setLayout(replay_layout)
        layout.addWidget(replay_group)
        
        return widget
    
    def create_subdomain_tab(self):
        """Create the subdomain discovery tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target Domain:"))
        self.subdomain_target = QLineEdit()
        self.subdomain_target.setPlaceholderText("e.g., example.com")
        target_layout.addWidget(self.subdomain_target)
        
        # Scan options
        options_layout = QHBoxLayout()
        
        # Recursive toggle
        self.recursive_toggle = QCheckBox("Recursive")
        self.recursive_toggle.setChecked(True)
        options_layout.addWidget(self.recursive_toggle)
        
        # DNS server
        dns_layout = QHBoxLayout()
        dns_layout.addWidget(QLabel("DNS Server:"))
        self.dns_server = QLineEdit()
        self.dns_server.setPlaceholderText("Optional")
        dns_layout.addWidget(self.dns_server)
        options_layout.addLayout(dns_layout)
        
        layout.addLayout(target_layout)
        layout.addLayout(options_layout)
        
        # Scan and Stop buttons
        button_layout = QHBoxLayout()
        self.subdomain_scan_btn = QPushButton("Start Scan")
        self.subdomain_scan_btn.clicked.connect(self.start_subdomain_scan)
        button_layout.addWidget(self.subdomain_scan_btn)
        
        self.subdomain_stop_btn = QPushButton("Stop Scan")
        self.subdomain_stop_btn.clicked.connect(self.stop_subdomain_scan)
        self.subdomain_stop_btn.setEnabled(False)
        button_layout.addWidget(self.subdomain_stop_btn)
        
        layout.addLayout(button_layout)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.subdomain_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.subdomain_status_label)
        self.subdomain_progress = QProgressBar()
        self.subdomain_progress.setTextVisible(True)
        status_layout.addWidget(self.subdomain_progress)
        layout.addLayout(status_layout)
        
        # Results table
        self.subdomain_table = QTableWidget()
        self.subdomain_table.setColumnCount(3)
        self.subdomain_table.setHorizontalHeaderLabels(["Subdomain", "IP Address", "Status"])
        self.subdomain_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.subdomain_table)
        
        # Export button
        export_layout = QHBoxLayout()
        self.export_subdomains_btn = QPushButton("Export Results")
        self.export_subdomains_btn.clicked.connect(self.export_subdomains)
        self.export_subdomains_btn.setEnabled(False)
        export_layout.addWidget(self.export_subdomains_btn)
        layout.addLayout(export_layout)
        
        return widget
    
    def create_port_tab(self):
        """Create the port scanner tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.port_target = QLineEdit()
        self.port_target.setPlaceholderText("IP address or hostname")
        target_layout.addWidget(self.port_target)
        layout.addLayout(target_layout)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        # Port range
        port_range_layout = QHBoxLayout()
        port_range_layout.addWidget(QLabel("Port Range:"))
        self.port_start = QSpinBox()
        self.port_start.setRange(1, 65535)
        self.port_start.setValue(1)
        port_range_layout.addWidget(self.port_start)
        
        port_range_layout.addWidget(QLabel("-"))
        
        self.port_end = QSpinBox()
        self.port_end.setRange(1, 65535)
        self.port_end.setValue(1024)
        port_range_layout.addWidget(self.port_end)
        
        options_layout.addLayout(port_range_layout)
        
        # Scan type
        scan_type_layout = QHBoxLayout()
        scan_type_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP Connect", "SYN Scan", "UDP Scan", "Service Detection"])
        scan_type_layout.addWidget(self.scan_type)
        
        options_layout.addLayout(scan_type_layout)
        
        # Additional options
        additional_layout = QHBoxLayout()
        
        self.version_detect = QCheckBox("Version Detection")
        self.version_detect.setChecked(True)
        additional_layout.addWidget(self.version_detect)
        
        self.os_detect = QCheckBox("OS Detection")
        self.os_detect.setChecked(True)
        additional_layout.addWidget(self.os_detect)
        
        self.aggressive = QCheckBox("Aggressive")
        self.aggressive.setChecked(False)
        additional_layout.addWidget(self.aggressive)
        
        options_layout.addLayout(additional_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Scan and Stop buttons
        button_layout = QHBoxLayout()
        self.port_scan_btn = QPushButton("Start Scan")
        self.port_scan_btn.clicked.connect(self.start_port_scan)
        button_layout.addWidget(self.port_scan_btn)
        
        self.port_stop_btn = QPushButton("Stop Scan")
        self.port_stop_btn.clicked.connect(self.stop_port_scan)
        self.port_stop_btn.setEnabled(False)
        button_layout.addWidget(self.port_stop_btn)
        
        layout.addLayout(button_layout)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.port_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.port_status_label)
        self.port_progress = QProgressBar()
        self.port_progress.setTextVisible(True)
        status_layout.addWidget(self.port_progress)
        layout.addLayout(status_layout)
        
        # Results table
        self.port_table = QTableWidget()
        self.port_table.setColumnCount(5)
        self.port_table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service", "Version"])
        self.port_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.port_table)
        
        # Export button
        export_layout = QHBoxLayout()
        self.export_ports_btn = QPushButton("Export Results")
        self.export_ports_btn.clicked.connect(self.export_ports)
        self.export_ports_btn.setEnabled(False)
        export_layout.addWidget(self.export_ports_btn)
        layout.addLayout(export_layout)
        
        return widget
    
    def create_fuzzer_tab(self):
        """Create the directory fuzzer tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target URL:"))
        self.fuzzer_target = QLineEdit()
        self.fuzzer_target.setPlaceholderText("e.g., http://example.com")
        target_layout.addWidget(self.fuzzer_target)
        layout.addLayout(target_layout)
        
        # Fuzzing options
        options_group = QGroupBox("Fuzzing Options")
        options_layout = QVBoxLayout()
        
        # Wordlist selection
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        self.wordlist_path = QLineEdit()
        wordlist_layout.addWidget(self.wordlist_path)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_wordlist)
        wordlist_layout.addWidget(browse_btn)
        
        options_layout.addLayout(wordlist_layout)
        
        # Additional options
        additional_layout = QHBoxLayout()
        
        self.recursive_fuzz = QCheckBox("Recursive")
        self.recursive_fuzz.setChecked(True)
        additional_layout.addWidget(self.recursive_fuzz)
        
        self.follow_redirects = QCheckBox("Follow Redirects")
        self.follow_redirects.setChecked(True)
        additional_layout.addWidget(self.follow_redirects)
        
        self.verify_ssl = QCheckBox("Verify SSL")
        self.verify_ssl.setChecked(False)
        additional_layout.addWidget(self.verify_ssl)
        
        options_layout.addLayout(additional_layout)
        
        # HTTP methods
        methods_layout = QHBoxLayout()
        methods_layout.addWidget(QLabel("Methods:"))
        self.http_methods = QComboBox()
        self.http_methods.addItems(["GET", "POST", "HEAD", "OPTIONS"])
        self.http_methods.setEditable(True)
        self.http_methods.setInsertPolicy(QComboBox.InsertPolicy.InsertAlphabetically)
        methods_layout.addWidget(self.http_methods)
        
        options_layout.addLayout(methods_layout)
        
        # Status codes
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status Codes:"))
        self.status_codes = QLineEdit()
        self.status_codes.setPlaceholderText("e.g., 200,301,401,403")
        self.status_codes.setText("200,301,401,403")
        status_layout.addWidget(self.status_codes)
        
        options_layout.addLayout(status_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Scan and Stop buttons
        button_layout = QHBoxLayout()
        self.fuzzer_scan_btn = QPushButton("Start Fuzzing")
        self.fuzzer_scan_btn.clicked.connect(self.start_fuzzing)
        button_layout.addWidget(self.fuzzer_scan_btn)
        
        self.fuzzer_stop_btn = QPushButton("Stop Fuzzing")
        self.fuzzer_stop_btn.clicked.connect(self.stop_fuzzing)
        self.fuzzer_stop_btn.setEnabled(False)
        button_layout.addWidget(self.fuzzer_stop_btn)
        
        layout.addLayout(button_layout)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.fuzzer_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.fuzzer_status_label)
        self.fuzzer_progress = QProgressBar()
        self.fuzzer_progress.setTextVisible(True)
        status_layout.addWidget(self.fuzzer_progress)
        layout.addLayout(status_layout)
        
        # Results table
        self.fuzzer_table = QTableWidget()
        self.fuzzer_table.setColumnCount(4)
        self.fuzzer_table.setHorizontalHeaderLabels(["URL", "Method", "Status Code", "Content Length"])
        self.fuzzer_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.fuzzer_table)
        
        # Export button
        export_layout = QHBoxLayout()
        self.export_fuzzer_btn = QPushButton("Export Results")
        self.export_fuzzer_btn.clicked.connect(self.export_fuzzer_results)
        self.export_fuzzer_btn.setEnabled(False)
        export_layout.addWidget(self.export_fuzzer_btn)
        layout.addLayout(export_layout)
        
        return widget
    
    def create_vulnerability_tab(self):
        """Create the vulnerability scanning tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., http://example.com or IP address")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        # Tool selection
        tool_layout = QHBoxLayout()
        tool_layout.addWidget(QLabel("Tools:"))
        self.tool_combo = QComboBox()
        self.tool_combo.addItems(["All", "Nuclei", "Nmap", "XSStrike"])
        tool_layout.addWidget(self.tool_combo)
        layout.addLayout(tool_layout)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        # Additional options
        additional_layout = QHBoxLayout()
        
        self.verify_ssl = QCheckBox("Verify SSL")
        self.verify_ssl.setChecked(False)
        additional_layout.addWidget(self.verify_ssl)
        
        self.follow_redirects = QCheckBox("Follow Redirects")
        self.follow_redirects.setChecked(True)
        additional_layout.addWidget(self.follow_redirects)
        
        self.aggressive = QCheckBox("Aggressive Scan")
        self.aggressive.setChecked(False)
        additional_layout.addWidget(self.aggressive)
        
        options_layout.addLayout(additional_layout)
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Scan controls
        control_layout = QHBoxLayout()
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.clicked.connect(self.start_vulnerability_scan)
        control_layout.addWidget(self.start_scan_btn)
        
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.clicked.connect(self.stop_vulnerability_scan)
        self.stop_scan_btn.setEnabled(False)
        control_layout.addWidget(self.stop_scan_btn)
        
        layout.addLayout(control_layout)
        
        # Status and progress
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        status_layout.addWidget(self.progress_bar)
        layout.addLayout(status_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Tool", "Type", "Details", "Severity"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.results_table)
        
        # Export button
        export_layout = QHBoxLayout()
        self.export_vuln_btn = QPushButton("Export Results")
        self.export_vuln_btn.clicked.connect(self.export_vulnerability_results)
        self.export_vuln_btn.setEnabled(False)
        export_layout.addWidget(self.export_vuln_btn)
        layout.addLayout(export_layout)
        
        return widget
    
    def create_report_tab(self):
        """Create the reporting tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report controls
        controls = QHBoxLayout()
        
        self.generate_report_btn = QPushButton("Generate Report")
        self.generate_report_btn.clicked.connect(self.generate_report)
        controls.addWidget(self.generate_report_btn)
        
        self.export_report_btn = QPushButton("Export Report")
        self.export_report_btn.clicked.connect(self.export_report)
        controls.addWidget(self.export_report_btn)
        
        layout.addLayout(controls)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.report_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.report_status_label)
        self.report_progress = QProgressBar()
        self.report_progress.setTextVisible(False)  # Hide percentage
        status_layout.addWidget(self.report_progress)
        layout.addLayout(status_layout)
        
        # Report preview
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        layout.addWidget(self.report_preview)
        
        return widget
    
    def start_proxy(self):
        """Start the proxy server."""
        try:
            port = self.proxy_port.value()
            ssl_enabled = self.ssl_toggle.isChecked()
            
            # Configure proxy with SSL settings
            self.proxy.configure(ssl_enabled=ssl_enabled)
            self.proxy.start(port=port)
            
            self.proxy_start_btn.setEnabled(False)
            self.proxy_stop_btn.setEnabled(True)
            self.proxy_status_label.setText(f"Status: Running on port {port}")
            self.proxy_log.append(f"Proxy started on port {port}")
            
            QMessageBox.information(self, "Success", "Proxy server started successfully!")
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            self.proxy_status_label.setText("Status: Failed to start")
            self.proxy_log.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to start proxy: {str(e)}")
    
    def stop_proxy(self):
        """Stop the proxy server."""
        try:
            self.proxy.stop()
            self.proxy_start_btn.setEnabled(True)
            self.proxy_stop_btn.setEnabled(False)
            self.proxy_status_label.setText("Status: Stopped")
            self.proxy_log.append("Proxy stopped")
            
            QMessageBox.information(self, "Success", "Proxy server stopped successfully!")
        except Exception as e:
            logger.error(f"Failed to stop proxy: {e}")
            self.proxy_status_label.setText("Status: Error stopping")
            self.proxy_log.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to stop proxy: {str(e)}")
    
    def add_token_pattern(self):
        """Add a token extraction pattern."""
        pattern = self.token_pattern.text().strip()
        if not pattern:
            QMessageBox.warning(self, "Warning", "Please enter a pattern!")
            return
        
        try:
            self.proxy.add_token_pattern(pattern)
            row = self.token_table.rowCount()
            self.token_table.insertRow(row)
            self.token_table.setItem(row, 0, QTableWidgetItem("Pattern"))
            self.token_table.setItem(row, 1, QTableWidgetItem(pattern))
            self.token_table.setItem(row, 2, QTableWidgetItem("Custom"))
            
            self.token_pattern.clear()
            self.proxy_log.append(f"Added token pattern: {pattern}")
        except Exception as e:
            logger.error(f"Failed to add token pattern: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add pattern: {str(e)}")
    
    def add_modification(self):
        """Add a request/response modification rule."""
        pattern = self.pattern_input.text().strip()
        replacement = self.replacement_input.text().strip()
        
        if not pattern or not replacement:
            QMessageBox.warning(self, "Warning", "Please enter both pattern and replacement!")
            return
        
        try:
            self.proxy.add_modification(pattern, replacement)
            row = self.mod_table.rowCount()
            self.mod_table.insertRow(row)
            self.mod_table.setItem(row, 0, QTableWidgetItem(pattern))
            self.mod_table.setItem(row, 1, QTableWidgetItem(replacement))
            
            self.pattern_input.clear()
            self.replacement_input.clear()
            self.proxy_log.append(f"Added modification rule: {pattern} -> {replacement}")
        except Exception as e:
            logger.error(f"Failed to add modification rule: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add modification: {str(e)}")
    
    def replay_request(self):
        """Replay a selected request."""
        selected_rows = self.replay_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "Warning", "Please select a request to replay!")
            return
        
        try:
            row = selected_rows[0].row()
            request = {
                "method": self.replay_table.item(row, 0).text(),
                "url": self.replay_table.item(row, 1).text(),
                "headers": json.loads(self.replay_table.item(row, 2).text()),
                "body": self.replay_table.item(row, 3).text()
            }
            
            self.proxy.add_to_replay_queue(request)
            self.proxy_log.append(f"Added request to replay queue: {request['method']} {request['url']}")
            QMessageBox.information(self, "Success", "Request added to replay queue!")
        except Exception as e:
            logger.error(f"Failed to replay request: {e}")
            QMessageBox.critical(self, "Error", f"Failed to replay request: {str(e)}")
    
    def clear_replay_table(self):
        """Clear the request replay table."""
        self.replay_table.setRowCount(0)
        self.proxy_log.append("Cleared replay table")
    
    def start_subdomain_scan(self):
        """Start subdomain discovery scan."""
        target = self.subdomain_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target domain!")
            return
        
        try:
            # Reset UI
            self.subdomain_scan_btn.setEnabled(False)
            self.subdomain_stop_btn.setEnabled(True)
            self.subdomain_progress.setValue(0)
            self.subdomain_status_label.setText("Status: Initializing scan...")
            self.subdomain_table.setRowCount(0)
            self.export_subdomains_btn.setEnabled(False)
            
            # Get scan options
            options = {
                "recursive": self.recursive_toggle.isChecked(),
                "dns_server": self.dns_server.text().strip() if self.dns_server.text().strip() else None
            }
            
            # Initialize scan worker
            self.scan_worker = ScanWorker("subdomain", target, options)
            self.scan_worker.progress.connect(self.update_subdomain_progress)
            self.scan_worker.status.connect(self.update_subdomain_status)
            self.scan_worker.finished.connect(self.handle_subdomain_results)
            self.scan_worker.error.connect(self.handle_scan_error)
            
            # Start scan
            self.scan_worker.start()
            
        except Exception as e:
            logger.error(f"Failed to start subdomain scan: {e}")
            self.handle_scan_error(str(e))
    
    def stop_subdomain_scan(self):
        """Stop the subdomain scan."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()
            self.subdomain_scan_btn.setEnabled(True)
            self.subdomain_stop_btn.setEnabled(False)
            self.subdomain_status_label.setText("Status: Scan stopped")
    
    def update_subdomain_progress(self, value):
        """Update subdomain scan progress."""
        self.subdomain_progress.setValue(value)
    
    def update_subdomain_status(self, message):
        """Update subdomain scan status."""
        self.subdomain_status_label.setText(f"Status: {message}")
    
    def handle_subdomain_results(self, results):
        """Handle subdomain scan results."""
        try:
            if not isinstance(results, dict) or "subdomains" not in results:
                raise ValueError("Invalid results format")
            
            subdomains = results.get("subdomains", [])
            self.subdomain_table.setRowCount(len(subdomains))
            
            for i, subdomain in enumerate(subdomains):
                if not isinstance(subdomain, dict):
                    logger.error("Invalid subdomain format")
                    continue
                
                self.subdomain_table.setItem(i, 0, QTableWidgetItem(subdomain.get("name", "")))
                self.subdomain_table.setItem(i, 1, QTableWidgetItem(subdomain.get("ip", "")))
                self.subdomain_table.setItem(i, 2, QTableWidgetItem(subdomain.get("status", "Active")))
            
            self.subdomain_scan_btn.setEnabled(True)
            self.subdomain_stop_btn.setEnabled(False)
            self.subdomain_progress.setValue(100)
            self.subdomain_status_label.setText(f"Status: Found {len(subdomains)} subdomains")
            self.export_subdomains_btn.setEnabled(True)
            
        except Exception as e:
            logger.error(f"Error handling subdomain results: {e}")
            self.handle_scan_error(str(e))
    
    def export_subdomains(self):
        """Export subdomain results to a file."""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Subdomains",
                "",
                "Text Files (*.txt);;CSV Files (*.csv);;All Files (*.*)"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    if file_path.endswith('.csv'):
                        f.write("Subdomain,IP Address,Status\n")
                        for row in range(self.subdomain_table.rowCount()):
                            subdomain = self.subdomain_table.item(row, 0).text()
                            ip = self.subdomain_table.item(row, 1).text()
                            status = self.subdomain_table.item(row, 2).text()
                            f.write(f"{subdomain},{ip},{status}\n")
                    else:
                        for row in range(self.subdomain_table.rowCount()):
                            subdomain = self.subdomain_table.item(row, 0).text()
                            f.write(f"{subdomain}\n")
                
                QMessageBox.information(self, "Success", "Subdomains exported successfully!")
                
        except Exception as e:
            logger.error(f"Failed to export subdomains: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export subdomains: {str(e)}")
    
    def start_port_scan(self):
        """Start port scanning."""
        target = self.port_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target!")
            return
        
        try:
            # Reset UI
            self.port_scan_btn.setEnabled(False)
            self.port_stop_btn.setEnabled(True)
            self.port_progress.setValue(0)
            self.port_status_label.setText("Status: Initializing scan...")
            self.port_table.setRowCount(0)
            self.export_ports_btn.setEnabled(False)
            
            # Get scan options
            options = {
                "start_port": self.port_start.value(),
                "end_port": self.port_end.value(),
                "scan_type": self.scan_type.currentText(),
                "version_detect": self.version_detect.isChecked(),
                "os_detect": self.os_detect.isChecked(),
                "aggressive": self.aggressive.isChecked()
            }
            
            # Initialize scan worker
            self.scan_worker = ScanWorker("port", target, options)
            self.scan_worker.progress.connect(self.update_port_progress)
            self.scan_worker.status.connect(self.update_port_status)
            self.scan_worker.finished.connect(self.handle_port_results)
            self.scan_worker.error.connect(self.handle_scan_error)
            
            # Start scan
            self.scan_worker.start()
            
        except Exception as e:
            logger.error(f"Failed to start port scan: {e}")
            self.handle_scan_error(str(e))
    
    def stop_port_scan(self):
        """Stop the port scan."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()
            self.port_scan_btn.setEnabled(True)
            self.port_stop_btn.setEnabled(False)
            self.port_status_label.setText("Status: Scan stopped")
    
    def update_port_progress(self, value):
        """Update port scan progress."""
        self.port_progress.setValue(value)
    
    def update_port_status(self, message):
        """Update port scan status."""
        self.port_status_label.setText(f"Status: {message}")
    
    def handle_port_results(self, results):
        """Handle port scan results."""
        try:
            ports = results.get("ports", [])
            self.port_table.setRowCount(len(ports))
            
            for i, port in enumerate(ports):
                self.port_table.setItem(i, 0, QTableWidgetItem(str(port.get("number", ""))))
                self.port_table.setItem(i, 1, QTableWidgetItem(port.get("protocol", "")))
                self.port_table.setItem(i, 2, QTableWidgetItem(port.get("state", "")))
                self.port_table.setItem(i, 3, QTableWidgetItem(port.get("service", "")))
                self.port_table.setItem(i, 4, QTableWidgetItem(port.get("version", "")))
            
            open_ports = [port for port in ports if port.get("state") == "open"]
            self.port_scan_btn.setEnabled(True)
            self.port_stop_btn.setEnabled(False)
            self.port_progress.setValue(100)
            self.port_status_label.setText(f"Status: Found {len(open_ports)} open ports")
            self.export_ports_btn.setEnabled(True)
            
        except Exception as e:
            logger.error(f"Error handling port results: {e}")
            self.handle_scan_error(str(e))
    
    def export_ports(self):
        """Export port scan results to a file."""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Port Scan Results",
                "",
                "Text Files (*.txt);;CSV Files (*.csv);;All Files (*.*)"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    if file_path.endswith('.csv'):
                        f.write("Port,Protocol,State,Service,Version\n")
                        for row in range(self.port_table.rowCount()):
                            port = self.port_table.item(row, 0).text()
                            protocol = self.port_table.item(row, 1).text()
                            state = self.port_table.item(row, 2).text()
                            service = self.port_table.item(row, 3).text()
                            version = self.port_table.item(row, 4).text()
                            f.write(f"{port},{protocol},{state},{service},{version}\n")
                    else:
                        f.write("Port Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        for row in range(self.port_table.rowCount()):
                            port = self.port_table.item(row, 0).text()
                            protocol = self.port_table.item(row, 1).text()
                            state = self.port_table.item(row, 2).text()
                            service = self.port_table.item(row, 3).text()
                            version = self.port_table.item(row, 4).text()
                            f.write(f"Port: {port}/{protocol}\n")
                            f.write(f"State: {state}\n")
                            f.write(f"Service: {service}\n")
                            f.write(f"Version: {version}\n")
                            f.write("-" * 30 + "\n")
                
                QMessageBox.information(self, "Success", "Port scan results exported successfully!")
                
        except Exception as e:
            logger.error(f"Failed to export port scan results: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
    
    def start_fuzzing(self):
        """Start directory fuzzing."""
        target = self.fuzzer_target.text().strip()
        wordlist = self.wordlist_path.text().strip()
        
        if not target or not wordlist:
            QMessageBox.warning(self, "Warning", "Please enter both target URL and wordlist path!")
            return
        
        try:
            # Reset UI
            self.fuzzer_scan_btn.setEnabled(False)
            self.fuzzer_stop_btn.setEnabled(True)
            self.fuzzer_progress.setValue(0)
            self.fuzzer_status_label.setText("Status: Initializing fuzzer...")
            self.fuzzer_table.setRowCount(0)
            self.export_fuzzer_btn.setEnabled(False)
            
            # Get fuzzing options
            options = {
                "wordlist": wordlist,
                "recursive": self.recursive_fuzz.isChecked(),
                "follow_redirects": self.follow_redirects.isChecked(),
                "verify_ssl": self.verify_ssl.isChecked(),
                "methods": self.http_methods.currentText().split(","),
                "status_codes": [int(code.strip()) for code in self.status_codes.text().split(",")]
            }
            
            # Initialize scan worker
            self.scan_worker = ScanWorker("directory", target, options)
            self.scan_worker.progress.connect(self.update_fuzzer_progress)
            self.scan_worker.status.connect(self.update_fuzzer_status)
            self.scan_worker.finished.connect(self.handle_fuzzer_results)
            self.scan_worker.error.connect(self.handle_scan_error)
            
            # Start scan
            self.scan_worker.start()
            
        except Exception as e:
            logger.error(f"Failed to start fuzzing: {e}")
            self.handle_scan_error(str(e))
    
    def stop_fuzzing(self):
        """Stop the fuzzing process."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()
            self.fuzzer_scan_btn.setEnabled(True)
            self.fuzzer_stop_btn.setEnabled(False)
            self.fuzzer_status_label.setText("Status: Fuzzing stopped")
    
    def update_fuzzer_progress(self, value):
        """Update fuzzer progress."""
        self.fuzzer_progress.setValue(value)
    
    def update_fuzzer_status(self, message):
        """Update fuzzer status."""
        self.fuzzer_status_label.setText(f"Status: {message}")
    
    def handle_fuzzer_results(self, results):
        """Handle fuzzer results."""
        try:
            directories = results.get("directories", [])
            self.fuzzer_table.setRowCount(len(directories))
            
            for i, directory in enumerate(directories):
                self.fuzzer_table.setItem(i, 0, QTableWidgetItem(directory.get("url", "")))
                self.fuzzer_table.setItem(i, 1, QTableWidgetItem(directory.get("method", "")))
                self.fuzzer_table.setItem(i, 2, QTableWidgetItem(str(directory.get("status_code", ""))))
                self.fuzzer_table.setItem(i, 3, QTableWidgetItem(str(directory.get("content_length", ""))))
            
            self.fuzzer_scan_btn.setEnabled(True)
            self.fuzzer_stop_btn.setEnabled(False)
            self.fuzzer_progress.setValue(100)
            self.fuzzer_status_label.setText(f"Status: Found {len(directories)} directories")
            self.export_fuzzer_btn.setEnabled(True)
            
        except Exception as e:
            logger.error(f"Error handling fuzzer results: {e}")
            self.handle_scan_error(str(e))
    
    def export_fuzzer_results(self):
        """Export fuzzer results to a file."""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Fuzzer Results",
                "",
                "Text Files (*.txt);;CSV Files (*.csv);;All Files (*.*)"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    if file_path.endswith('.csv'):
                        f.write("URL,Method,Status Code,Content Length\n")
                        for row in range(self.fuzzer_table.rowCount()):
                            url = self.fuzzer_table.item(row, 0).text()
                            method = self.fuzzer_table.item(row, 1).text()
                            status = self.fuzzer_table.item(row, 2).text()
                            length = self.fuzzer_table.item(row, 3).text()
                            f.write(f"{url},{method},{status},{length}\n")
                    else:
                        f.write("Directory Fuzzing Results\n")
                        f.write("=" * 50 + "\n\n")
                        for row in range(self.fuzzer_table.rowCount()):
                            url = self.fuzzer_table.item(row, 0).text()
                            method = self.fuzzer_table.item(row, 1).text()
                            status = self.fuzzer_table.item(row, 2).text()
                            length = self.fuzzer_table.item(row, 3).text()
                            f.write(f"URL: {url}\n")
                            f.write(f"Method: {method}\n")
                            f.write(f"Status Code: {status}\n")
                            f.write(f"Content Length: {length}\n")
                            f.write("-" * 30 + "\n")
                
                QMessageBox.information(self, "Success", "Fuzzer results exported successfully!")
                
        except Exception as e:
            logger.error(f"Failed to export fuzzer results: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
    
    def browse_wordlist(self):
        """Browse for a wordlist file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Wordlist",
            "",
            "Text Files (*.txt);;All Files (*.*)"
        )
        if file_path:
            self.wordlist_path.setText(file_path)
    
    def start_vulnerability_scan(self):
        """Start a vulnerability scan."""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Error", "A scan is already running")
            return
        
        # Check if required tools are available
        tools = ExternalTools()
        missing_tools = []
        
        if self.tool_combo.currentText() in ["All", "Nuclei"]:
            if not Path(tools.tools['nuclei']['path']).exists():
                missing_tools.append("Nuclei")
        
        if self.tool_combo.currentText() in ["All", "Nmap"]:
            if not Path(tools.tools['nmap']['path']).exists():
                missing_tools.append("Nmap")
        
        if self.tool_combo.currentText() in ["All", "XSStrike"]:
            if not Path(tools.tools['xsstrike']['path']).exists():
                missing_tools.append("XSStrike")
        
        if missing_tools:
            QMessageBox.warning(
                self,
                "Missing Tools",
                f"The following tools are not installed: {', '.join(missing_tools)}\n"
                "Please install them before running the scan."
            )
            return
        
        # Initialize scan worker
        self.scan_worker = ScanWorker(
            "vulnerability",
            target,
            {"tools": self.tool_combo.currentText()}
        )
        
        # Connect signals
        self.scan_worker.progress.connect(self.update_progress)
        self.scan_worker.status.connect(self.update_status)
        self.scan_worker.finished.connect(self.handle_vuln_results)
        self.scan_worker.error.connect(self.handle_scan_error)
        
        # Update UI
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        
        # Start scan
        self.scan_worker.start()
    
    def stop_vulnerability_scan(self):
        """Stop the current vulnerability scan."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()
            self.start_scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
    
    def update_progress(self, value):
        """Update the progress bar."""
        self.progress_bar.setValue(value)
    
    def update_status(self, message):
        """Update the status label."""
        self.status_label.setText(message)
    
    def handle_vuln_results(self, results):
        """Handle vulnerability scan results."""
        try:
            self.results_table.setRowCount(0)
            
            if not isinstance(results, dict) or "vulnerabilities" not in results:
                raise ValueError("Invalid results format")
            
            for tool_name, tool_results in results["vulnerabilities"].items():
                if not isinstance(tool_results, dict):
                    logger.error(f"Invalid results format for {tool_name}")
                    continue
                
                if not tool_results.get("success"):
                    logger.error(f"{tool_name} scan failed: {tool_results.get('error')}")
                    continue
                
                findings = tool_results.get("findings", [])
                if not isinstance(findings, list):
                    logger.error(f"Invalid findings format for {tool_name}")
                    continue
                
                for finding in findings:
                    if not isinstance(finding, dict):
                        logger.error(f"Invalid finding format in {tool_name}")
                        continue
                        
                    row = self.results_table.rowCount()
                    self.results_table.insertRow(row)
                    
                    self.results_table.setItem(row, 0, QTableWidgetItem(tool_name))
                    self.results_table.setItem(row, 1, QTableWidgetItem(finding.get("type", "Unknown")))
                    self.results_table.setItem(row, 2, QTableWidgetItem(str(finding.get("details", ""))))
                    self.results_table.setItem(row, 3, QTableWidgetItem(finding.get("severity", "Unknown")))
            
            self.status_label.setText("Scan completed")
            self.start_scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
            self.export_vuln_btn.setEnabled(True)
            
        except Exception as e:
            logger.error(f"Error handling results: {e}")
            self.handle_scan_error(str(e))
    
    def handle_scan_error(self, error_message):
        """Handle scan errors."""
        logger.error(f"Scan error: {error_message}")
        QMessageBox.critical(self, "Error", f"Scan failed: {error_message}")
        self.status_label.setText("Scan failed")
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
    
    def generate_report(self):
        """Generate a report from scan results."""
        try:
            # Reset and prepare UI
            self.report_progress.setValue(0)
            self.generate_report_btn.setEnabled(False)
            self.export_report_btn.setEnabled(False)
            
            # Initialize report data
            self.report_status_label.setText("Status: Initializing report data...")
            self.report_progress.setValue(20)
            self.report_data = ReportData()
            self.report_data.set_scan_info("Target", "Scope")
            
            # Process scan results
            self.report_status_label.setText("Status: Processing scan results...")
            self.report_progress.setValue(40)
            
            # Add findings from various scans
            # This would be populated with actual scan results
            
            # Finalize report data
            self.report_status_label.setText("Status: Finalizing report data...")
            self.report_progress.setValue(60)
            self.report_data.finalize()
            
            # Generate HTML report
            self.report_status_label.setText("Status: Generating HTML report...")
            self.report_progress.setValue(80)
            reports = self.report_generator.generate_report(self.report_data.data, formats=['html'])
            
            # Display report
            self.report_status_label.setText("Status: Loading report preview...")
            self.report_progress.setValue(90)
            with open(reports['html'], 'r') as f:
                self.report_preview.setHtml(f.read())
            
            # Complete
            self.report_status_label.setText("Status: Report generated successfully")
            self.report_progress.setValue(100)
            self.generate_report_btn.setEnabled(True)
            self.export_report_btn.setEnabled(True)
            
            QMessageBox.information(self, "Success", "Report generated successfully!")
        except Exception as e:
            self.report_status_label.setText("Status: Error generating report")
            self.report_progress.setValue(0)
            self.generate_report_btn.setEnabled(True)
            self.export_report_btn.setEnabled(True)
            
            QMessageBox.critical(
                self, 
                "Error", 
                f"Failed to generate report: {str(e)}\n\n"
                "If you're trying to generate a PDF, please make sure wkhtmltopdf is installed:\n"
                "1. Download from https://wkhtmltopdf.org/downloads.html\n"
                "2. Install and ensure it's added to your system PATH"
            )
    
    def export_report(self):
        """Export the report in various formats."""
        try:
            if not self.report_data:
                QMessageBox.warning(
                    self,
                    "Warning",
                    "Please generate a report first before exporting."
                )
                return
                
            file_path, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Export Report",
                "",
                "HTML Files (*.html);;PDF Files (*.pdf);;JSON Files (*.json)"
            )
            
            if file_path:
                ext = os.path.splitext(file_path)[1].lower()
                try:
                    if ext == '.html':
                        self.report_generator.generate_html_report(self.report_data.data, file_path)
                    elif ext == '.pdf':
                        self.report_generator.generate_pdf_report(self.report_data.data, file_path)
                    elif ext == '.json':
                        self.report_generator.generate_json_report(self.report_data.data, file_path)
                    
                    QMessageBox.information(self, "Success", "Report exported successfully!")
                except RuntimeError as e:
                    if "wkhtmltopdf not found" in str(e):
                        QMessageBox.critical(
                            self,
                            "Error",
                            "wkhtmltopdf is required for PDF generation.\n\n"
                            "Please install it from: https://wkhtmltopdf.org/downloads.html\n"
                            "Make sure to check 'Add to PATH' during installation."
                        )
                    else:
                        raise
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def export_vulnerability_results(self):
        """Export vulnerability scan results to a file."""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Vulnerability Results",
                "",
                "Text Files (*.txt);;CSV Files (*.csv);;All Files (*.*)"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    if file_path.endswith('.csv'):
                        f.write("Tool,Type,Details,Severity\n")
                        for row in range(self.results_table.rowCount()):
                            tool = self.results_table.item(row, 0).text()
                            type_ = self.results_table.item(row, 1).text()
                            details = self.results_table.item(row, 2).text()
                            severity = self.results_table.item(row, 3).text()
                            f.write(f"{tool},{type_},{details},{severity}\n")
                    else:
                        f.write("Vulnerability Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        for row in range(self.results_table.rowCount()):
                            tool = self.results_table.item(row, 0).text()
                            type_ = self.results_table.item(row, 1).text()
                            details = self.results_table.item(row, 2).text()
                            severity = self.results_table.item(row, 3).text()
                            f.write(f"Tool: {tool}\n")
                            f.write(f"Type: {type_}\n")
                            f.write(f"Details: {details}\n")
                            f.write(f"Severity: {severity}\n")
                            f.write("-" * 30 + "\n")
                
                QMessageBox.information(self, "Success", "Vulnerability results exported successfully!")
                
        except Exception as e:
            logger.error(f"Failed to export vulnerability results: {e}")
            QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")

    def closeEvent(self, event):
        """Handle application close event."""
        # Clean up any running scan
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait()
        
        # Clean up proxy if running
        if hasattr(self, 'proxy') and self.proxy.is_running:
            self.proxy.stop()
        
        event.accept() 