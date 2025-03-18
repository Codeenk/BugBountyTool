from PySide6.QtWidgets import (QMainWindow, QWidget, QTabWidget,
                             QVBoxLayout, QPushButton, QLabel,
                             QLineEdit, QTextEdit, QSpinBox,
                             QMessageBox, QProgressBar, QHBoxLayout,
                             QComboBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QFileDialog, QGroupBox)
from PySide6.QtCore import Qt, Slot, QThread, Signal
from PySide6.QtGui import QFont, QIcon
import sys
import os
from pathlib import Path

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.modules.interceptor.advanced_proxy import AdvancedProxy
from src.modules.scanner.port_scanner import PortScanner
from src.modules.discovery.subdomain_finder import SubdomainFinder
from src.modules.fuzzer.directory_fuzzer import DirectoryFuzzer
from src.modules.database.storage import Storage
from src.modules.integration.external_tools import ExternalTools
from src.modules.reporting.report_generator import ReportGenerator, ReportData

class ScanWorker(QThread):
    progress = Signal(int)
    finished = Signal(dict)
    error = Signal(str)
    
    def __init__(self, scan_type, target, options=None):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.options = options or {}
        self.tools = ExternalTools()
    
    def run(self):
        try:
            if self.scan_type == "vulnerability":
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
                    # Calculate overall progress
                    tool_weight = 100 / total_tools
                    current_tool_progress = (tool_progress / 100) * tool_weight
                    overall_progress = int((completed_tools * tool_weight) + current_tool_progress)
                    self.progress.emit(overall_progress)
                
                # Run Nuclei if selected
                if run_nuclei:
                    print("Running Nuclei scan...")
                    results["nuclei"] = self.tools.run_nuclei(
                        self.target,
                        progress_callback=update_progress
                    )
                    completed_tools += 1
                
                # Run Nmap if selected
                if run_nmap:
                    print("Running Nmap vulnerability scan...")
                    results["nmap"] = self.tools.run_nmap(
                        self.target,
                        progress_callback=update_progress
                    )
                    completed_tools += 1
                
                # Run XSStrike if selected
                if run_xsstrike:
                    print("Running XSStrike scan...")
                    results["xsstrike"] = self.tools.run_xsstrike(
                        self.target,
                        progress_callback=update_progress
                    )
                    completed_tools += 1
                
                self.progress.emit(100)
                self.finished.emit({"vulnerabilities": results})
            
            elif self.scan_type == "full":
                # Run all scans
                results = {}
                
                # Subdomain scan
                finder = SubdomainFinder()
                finder.find_subdomains(self.target)
                results["subdomains"] = finder.get_results()
                self.progress.emit(20)
                
                # Port scan
                scanner = PortScanner()
                port_results = []
                def port_callback(scan_results):
                    nonlocal port_results
                    port_results = scan_results
                
                scanner.scan(
                    self.target,
                    ports="1-1024",
                    callback=port_callback
                )
                results["ports"] = port_results
                self.progress.emit(40)
                
                # Directory fuzzing
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
                results["directories"] = dir_results
                self.progress.emit(60)
                
                # Vulnerability scanning
                vuln_results = {}
                
                # Run Nuclei
                print("Running Nuclei scan...")
                vuln_results["nuclei"] = self.tools.run_nuclei(self.target)
                
                # Run Nmap
                print("Running Nmap vulnerability scan...")
                vuln_results["nmap"] = self.tools.run_nmap(self.target)
                
                # Run XSStrike
                print("Running XSStrike scan...")
                vuln_results["xsstrike"] = self.tools.run_xsstrike(self.target)
                
                results["vulnerabilities"] = vuln_results
                self.progress.emit(80)
                
                # Generate report
                report_data = ReportData()
                report_data.set_scan_info(self.target, "Full Scan")
                
                for subdomain in results["subdomains"]:
                    report_data.add_subdomain(subdomain)
                
                for port in results["ports"]:
                    report_data.add_port(port)
                
                for vuln in results["vulnerabilities"].values():
                    if vuln.get("success"):
                        report_data.add_vulnerability(vuln)
                
                report_data.finalize()
                results["report"] = report_data.data
                self.progress.emit(100)
                
                self.finished.emit(results)
            
            else:
                # Handle other scan types...
                pass
        
        except Exception as e:
            self.error.emit(str(e))
            print(f"Scan error: {e}")  # Debug logging

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bug Bounty Tool")
        self.setMinimumSize(1200, 800)
        
        # Initialize components
        self.proxy = AdvancedProxy()
        self.storage = Storage()
        self.report_generator = ReportGenerator()
        self.report_data = None  # Initialize report_data attribute
        
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
        
        self.proxy_start_btn = QPushButton("Start Proxy")
        self.proxy_start_btn.clicked.connect(self.start_proxy)
        controls.addWidget(self.proxy_start_btn)
        
        self.proxy_stop_btn = QPushButton("Stop Proxy")
        self.proxy_stop_btn.clicked.connect(self.stop_proxy)
        self.proxy_stop_btn.setEnabled(False)
        controls.addWidget(self.proxy_stop_btn)
        
        layout.addLayout(controls)
        
        # Token extraction
        token_group = QGroupBox("Token Extraction")
        token_layout = QVBoxLayout()
        
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
        
        mod_group.setLayout(mod_layout)
        layout.addWidget(mod_group)
        
        # Request replay
        replay_group = QGroupBox("Request Replay")
        replay_layout = QVBoxLayout()
        
        self.replay_table = QTableWidget()
        self.replay_table.setColumnCount(4)
        self.replay_table.setHorizontalHeaderLabels(["Method", "URL", "Headers", "Body"])
        self.replay_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        replay_layout.addWidget(self.replay_table)
        
        replay_controls = QHBoxLayout()
        self.replay_btn = QPushButton("Replay Selected")
        self.replay_btn.clicked.connect(self.replay_request)
        replay_controls.addWidget(self.replay_btn)
        
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
        target_layout.addWidget(self.subdomain_target)
        
        # Scan and Stop buttons
        self.subdomain_scan_btn = QPushButton("Start Scan")
        self.subdomain_scan_btn.clicked.connect(self.start_subdomain_scan)
        target_layout.addWidget(self.subdomain_scan_btn)
        
        self.subdomain_stop_btn = QPushButton("Stop Scan")
        self.subdomain_stop_btn.clicked.connect(self.stop_current_scan)
        self.subdomain_stop_btn.setEnabled(False)
        target_layout.addWidget(self.subdomain_stop_btn)
        
        layout.addLayout(target_layout)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.subdomain_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.subdomain_status_label)
        self.subdomain_progress = QProgressBar()
        self.subdomain_progress.setTextVisible(False)
        status_layout.addWidget(self.subdomain_progress)
        layout.addLayout(status_layout)
        
        # Results table
        self.subdomain_table = QTableWidget()
        self.subdomain_table.setColumnCount(1)
        self.subdomain_table.setHorizontalHeaderLabels(["Subdomain"])
        self.subdomain_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.subdomain_table)
        
        return widget
    
    def create_port_tab(self):
        """Create the port scanner tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.port_target = QLineEdit()
        target_layout.addWidget(self.port_target)
        
        # Scan and Stop buttons
        self.port_scan_btn = QPushButton("Start Scan")
        self.port_scan_btn.clicked.connect(self.start_port_scan)
        target_layout.addWidget(self.port_scan_btn)
        
        self.port_stop_btn = QPushButton("Stop Scan")
        self.port_stop_btn.clicked.connect(self.stop_current_scan)
        self.port_stop_btn.setEnabled(False)
        target_layout.addWidget(self.port_stop_btn)
        
        layout.addLayout(target_layout)
        
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
        
        layout.addLayout(port_range_layout)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.port_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.port_status_label)
        self.port_progress = QProgressBar()
        self.port_progress.setTextVisible(False)
        status_layout.addWidget(self.port_progress)
        layout.addLayout(status_layout)
        
        # Results table
        self.port_table = QTableWidget()
        self.port_table.setColumnCount(4)
        self.port_table.setHorizontalHeaderLabels(["Port", "Service", "Version", "State"])
        self.port_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.port_table)
        
        return widget
    
    def create_fuzzer_tab(self):
        """Create the directory fuzzer tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target URL:"))
        self.fuzzer_target = QLineEdit()
        target_layout.addWidget(self.fuzzer_target)
        
        # Scan and Stop buttons
        self.fuzzer_scan_btn = QPushButton("Start Fuzzing")
        self.fuzzer_scan_btn.clicked.connect(self.start_fuzzing)
        target_layout.addWidget(self.fuzzer_scan_btn)
        
        self.fuzzer_stop_btn = QPushButton("Stop Fuzzing")
        self.fuzzer_stop_btn.clicked.connect(self.stop_current_scan)
        self.fuzzer_stop_btn.setEnabled(False)
        target_layout.addWidget(self.fuzzer_stop_btn)
        
        layout.addLayout(target_layout)
        
        # Wordlist selection
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        self.wordlist_path = QLineEdit()
        wordlist_layout.addWidget(self.wordlist_path)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_wordlist)
        wordlist_layout.addWidget(browse_btn)
        
        layout.addLayout(wordlist_layout)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.fuzzer_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.fuzzer_status_label)
        self.fuzzer_progress = QProgressBar()
        self.fuzzer_progress.setTextVisible(False)
        status_layout.addWidget(self.fuzzer_progress)
        layout.addLayout(status_layout)
        
        # Results table
        self.fuzzer_table = QTableWidget()
        self.fuzzer_table.setColumnCount(2)
        self.fuzzer_table.setHorizontalHeaderLabels(["Directory", "Status Code"])
        self.fuzzer_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.fuzzer_table)
        
        return widget
    
    def create_vulnerability_tab(self):
        """Create the vulnerability scanner tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.vuln_target = QLineEdit()
        target_layout.addWidget(self.vuln_target)
        
        # Tool selection
        tool_layout = QHBoxLayout()
        tool_layout.addWidget(QLabel("Tools:"))
        self.tool_selection = QComboBox()
        self.tool_selection.addItems(["All", "Nuclei", "Nmap", "XSStrike"])
        tool_layout.addWidget(self.tool_selection)
        
        # Scan and Stop buttons
        button_layout = QHBoxLayout()
        self.vuln_scan_btn = QPushButton("Start Scan")
        self.vuln_scan_btn.clicked.connect(self.start_vulnerability_scan)
        button_layout.addWidget(self.vuln_scan_btn)
        
        self.vuln_stop_btn = QPushButton("Stop Scan")
        self.vuln_stop_btn.clicked.connect(self.stop_current_scan)
        self.vuln_stop_btn.setEnabled(False)
        button_layout.addWidget(self.vuln_stop_btn)
        
        layout.addLayout(target_layout)
        layout.addLayout(tool_layout)
        layout.addLayout(button_layout)
        
        # Status layout
        status_layout = QHBoxLayout()
        self.vuln_status_label = QLabel("Status: Ready")
        status_layout.addWidget(self.vuln_status_label)
        self.vuln_progress = QProgressBar()
        self.vuln_progress.setTextVisible(False)
        status_layout.addWidget(self.vuln_progress)
        layout.addLayout(status_layout)
        
        # Results table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["Tool", "Type", "Target", "Port/Service", "Severity"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.vuln_table)
        
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
            self.proxy.start()
            self.proxy_start_btn.setEnabled(False)
            self.proxy_stop_btn.setEnabled(True)
            QMessageBox.information(self, "Success", "Proxy server started successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start proxy: {str(e)}")
    
    def stop_proxy(self):
        """Stop the proxy server."""
        try:
            self.proxy.stop()
            self.proxy_start_btn.setEnabled(True)
            self.proxy_stop_btn.setEnabled(False)
            QMessageBox.information(self, "Success", "Proxy server stopped successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to stop proxy: {str(e)}")
    
    def add_modification(self):
        """Add a request/response modification rule."""
        pattern = self.pattern_input.text()
        replacement = self.replacement_input.text()
        
        if pattern and replacement:
            self.proxy.add_modification(pattern, replacement)
            self.pattern_input.clear()
            self.replacement_input.clear()
            QMessageBox.information(self, "Success", "Modification rule added successfully!")
        else:
            QMessageBox.warning(self, "Warning", "Please enter both pattern and replacement!")
    
    def replay_request(self):
        """Replay a selected request."""
        selected_rows = self.replay_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "Warning", "Please select a request to replay!")
            return
        
        row = selected_rows[0].row()
        request = {
            "method": self.replay_table.item(row, 0).text(),
            "url": self.replay_table.item(row, 1).text(),
            "headers": json.loads(self.replay_table.item(row, 2).text()),
            "body": self.replay_table.item(row, 3).text()
        }
        
        self.proxy.add_to_replay_queue(request)
        QMessageBox.information(self, "Success", "Request added to replay queue!")
    
    def start_subdomain_scan(self):
        """Start subdomain discovery scan."""
        target = self.subdomain_target.text()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target domain!")
            return
        
        self.subdomain_scan_btn.setEnabled(False)
        self.subdomain_stop_btn.setEnabled(True)
        self.subdomain_progress.setValue(0)
        self.subdomain_status_label.setText("Status: Initializing scan...")
        
        self.scan_worker = ScanWorker("subdomain", target)
        self.scan_worker.progress.connect(self.update_subdomain_progress)
        self.scan_worker.finished.connect(self.handle_subdomain_results)
        self.scan_worker.error.connect(self.handle_scan_error)
        self.scan_worker.start()
    
    def start_port_scan(self):
        """Start port scanning."""
        target = self.port_target.text()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target!")
            return
        
        self.port_scan_btn.setEnabled(False)
        self.port_stop_btn.setEnabled(True)
        self.port_progress.setValue(0)
        self.port_status_label.setText("Status: Initializing scan...")
        
        options = {
            "start_port": self.port_start.value(),
            "end_port": self.port_end.value()
        }
        
        self.scan_worker = ScanWorker("port", target, options)
        self.scan_worker.progress.connect(self.update_port_progress)
        self.scan_worker.finished.connect(self.handle_port_results)
        self.scan_worker.error.connect(self.handle_scan_error)
        self.scan_worker.start()
    
    def start_fuzzing(self):
        """Start directory fuzzing."""
        target = self.fuzzer_target.text()
        wordlist = self.wordlist_path.text()
        
        if not target or not wordlist:
            QMessageBox.warning(self, "Warning", "Please enter both target URL and wordlist path!")
            return
        
        self.fuzzer_scan_btn.setEnabled(False)
        self.fuzzer_stop_btn.setEnabled(True)
        self.fuzzer_progress.setValue(0)
        self.fuzzer_status_label.setText("Status: Initializing fuzzer...")
        
        options = {"wordlist": wordlist}
        
        self.scan_worker = ScanWorker("directory", target, options)
        self.scan_worker.progress.connect(self.update_fuzzer_progress)
        self.scan_worker.finished.connect(self.handle_fuzzer_results)
        self.scan_worker.error.connect(self.handle_scan_error)
        self.scan_worker.start()
    
    def start_vulnerability_scan(self):
        """Start vulnerability scanning."""
        target = self.vuln_target.text()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target!")
            return
        
        # Prevent starting a new scan if one is already running
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Warning", "A scan is already in progress!")
            return
        
        # Clean up any previous scan worker
        self.cleanup_scan_worker()
        
        # Check for required tools before starting
        tools = ExternalTools()
        missing_tools = []
        selected_tool = self.tool_selection.currentText()
        
        try:
            if selected_tool == "All" or selected_tool == "Nuclei":
                if not tools.check_nuclei():
                    missing_tools.append("Nuclei")
            if selected_tool == "All" or selected_tool == "Nmap":
                if not tools.check_nmap():
                    missing_tools.append("Nmap")
            if selected_tool == "All" or selected_tool == "XSStrike":
                if not tools.check_xsstrike():
                    missing_tools.append("XSStrike")
            
            if missing_tools:
                instructions = {
                    "Nuclei": "1. Download from https://github.com/projectdiscovery/nuclei/releases\n"
                             "2. Extract the nuclei binary to the tools/nuclei directory\n"
                             "3. Ensure the binary is named 'nuclei.exe' on Windows or 'nuclei' on Linux/Mac",
                    "Nmap": "1. Download from https://nmap.org/download.html\n"
                           "2. Install and ensure it's added to your system PATH",
                    "XSStrike": "1. Clone from: https://github.com/s0md3v/XSStrike\n"
                               "2. Place in the tools/XSStrike directory\n"
                               "3. Run: pip install -r requirements.txt in the XSStrike directory"
                }
                
                msg = "The following tools need to be installed:\n\n"
                for tool in missing_tools:
                    msg += f"\n{tool}:\n{instructions[tool]}\n"
                
                QMessageBox.critical(self, "Missing Required Tools", msg)
                return
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error checking tools: {str(e)}")
            return
        
        self.vuln_scan_btn.setEnabled(False)
        self.vuln_stop_btn.setEnabled(True)
        self.vuln_progress.setValue(0)
        self.vuln_status_label.setText("Status: Initializing vulnerability scan...")
        
        options = {"tools": selected_tool}
        
        # Create and set up the scan worker
        self.scan_worker = ScanWorker("vulnerability", target, options)
        self.scan_worker.progress.connect(self.update_vuln_progress)
        self.scan_worker.finished.connect(self.handle_vuln_results)
        self.scan_worker.error.connect(self.handle_scan_error)
        self.scan_worker.finished.connect(lambda: self.cleanup_scan_worker())
        self.scan_worker.start()
    
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
    
    def update_subdomain_progress(self, value):
        """Update subdomain scan progress."""
        self.subdomain_progress.setValue(value)
        if value < 100:
            self.subdomain_status_label.setText(f"Status: Discovering subdomains... ({value}%)")
    
    def update_port_progress(self, value):
        """Update port scan progress."""
        self.port_progress.setValue(value)
        if value < 100:
            self.port_status_label.setText(f"Status: Scanning ports... ({value}%)")
    
    def update_fuzzer_progress(self, value):
        """Update fuzzer progress."""
        self.fuzzer_progress.setValue(value)
        if value < 100:
            self.fuzzer_status_label.setText(f"Status: Fuzzing directories... ({value}%)")
    
    def update_vuln_progress(self, value):
        """Update vulnerability scan progress."""
        self.vuln_progress.setValue(value)
        if value < 100:
            self.vuln_status_label.setText(f"Status: Running vulnerability scan... ({value}%)")
    
    def handle_subdomain_results(self, results):
        """Handle subdomain scan results."""
        self.subdomain_table.setRowCount(len(results["subdomains"]))
        for i, subdomain in enumerate(results["subdomains"]):
            self.subdomain_table.setItem(i, 0, QTableWidgetItem(subdomain))
        
        self.subdomain_scan_btn.setEnabled(True)
        self.subdomain_stop_btn.setEnabled(False)
        self.subdomain_progress.setValue(100)
        self.subdomain_status_label.setText(f"Status: Found {len(results['subdomains'])} subdomains")
    
    def handle_port_results(self, results):
        """Handle port scan results."""
        open_ports = [port for port in results["ports"] if port["state"] == "open"]
        self.port_table.setRowCount(len(results["ports"]))
        for i, port in enumerate(results["ports"]):
            self.port_table.setItem(i, 0, QTableWidgetItem(str(port["number"])))
            self.port_table.setItem(i, 1, QTableWidgetItem(port["service"]))
            self.port_table.setItem(i, 2, QTableWidgetItem(port["version"]))
            self.port_table.setItem(i, 3, QTableWidgetItem(port["state"]))
        
        self.port_scan_btn.setEnabled(True)
        self.port_stop_btn.setEnabled(False)
        self.port_progress.setValue(100)
        self.port_status_label.setText(f"Status: Found {len(open_ports)} open ports")
    
    def handle_fuzzer_results(self, results):
        """Handle fuzzer results."""
        self.fuzzer_table.setRowCount(len(results["directories"]))
        for i, directory in enumerate(results["directories"]):
            self.fuzzer_table.setItem(i, 0, QTableWidgetItem(directory["path"]))
            self.fuzzer_table.setItem(i, 1, QTableWidgetItem(str(directory["status_code"])))
        
        self.fuzzer_scan_btn.setEnabled(True)
        self.fuzzer_stop_btn.setEnabled(False)
        self.fuzzer_progress.setValue(100)
        self.fuzzer_status_label.setText(f"Status: Found {len(results['directories'])} directories")
    
    def handle_vuln_results(self, results):
        """Handle vulnerability scan results."""
        vulns = []
        for tool, result in results.get("vulnerabilities", {}).items():
            if result.get("success"):
                for finding in result.get("findings", []):
                    if isinstance(finding, str):
                        vulns.append({
                            "tool": tool,
                            "type": "Finding",
                            "target": self.vuln_target.text(),
                            "port_service": "N/A",
                            "severity": "Unknown"
                        })
                    else:
                        if tool == "nmap":
                            port_service = f"{finding.get('port', '')}/{finding.get('service', '')}"
                            target = f"{finding.get('host', '')} ({finding.get('hostname', '')})"
                        else:
                            port_service = "N/A"
                            target = finding.get("url", self.vuln_target.text())
                        
                        vulns.append({
                            "tool": tool,
                            "type": finding.get("type", "Unknown"),
                            "target": target,
                            "port_service": port_service,
                            "severity": finding.get("severity", "Unknown")
                        })
            else:
                print(f"Error in {tool}: {result.get('error', 'Unknown error')}")
        
        self.vuln_table.setRowCount(len(vulns))
        for i, vuln in enumerate(vulns):
            self.vuln_table.setItem(i, 0, QTableWidgetItem(vuln["tool"]))
            self.vuln_table.setItem(i, 1, QTableWidgetItem(vuln["type"]))
            self.vuln_table.setItem(i, 2, QTableWidgetItem(vuln["target"]))
            self.vuln_table.setItem(i, 3, QTableWidgetItem(vuln["port_service"]))
            self.vuln_table.setItem(i, 4, QTableWidgetItem(vuln["severity"]))
        
        self.vuln_scan_btn.setEnabled(True)
        self.vuln_stop_btn.setEnabled(False)
        self.vuln_progress.setValue(100)
        self.vuln_status_label.setText(f"Status: Found {len(vulns)} vulnerabilities")
    
    def handle_scan_error(self, error):
        """Handle scan errors."""
        QMessageBox.critical(self, "Error", f"Scan failed: {error}")
        
        # Update status labels and re-enable buttons
        self.subdomain_status_label.setText("Status: Error occurred")
        self.subdomain_scan_btn.setEnabled(True)
        self.subdomain_stop_btn.setEnabled(False)
        
        self.port_status_label.setText("Status: Error occurred")
        self.port_scan_btn.setEnabled(True)
        self.port_stop_btn.setEnabled(False)
        
        self.fuzzer_status_label.setText("Status: Error occurred")
        self.fuzzer_scan_btn.setEnabled(True)
        self.fuzzer_stop_btn.setEnabled(False)
        
        self.vuln_status_label.setText("Status: Error occurred")
        self.vuln_scan_btn.setEnabled(True)
        self.vuln_stop_btn.setEnabled(False)
        
        # Clean up the scan worker
        self.cleanup_scan_worker()
    
    def cleanup_scan_worker(self):
        """Clean up the scan worker thread."""
        if self.scan_worker:
            if self.scan_worker.isRunning():
                # Stop any running external tools
                if hasattr(self.scan_worker, 'tools'):
                    self.scan_worker.tools.stop_current_scan()
                self.scan_worker.terminate()
                self.scan_worker.wait()
            self.scan_worker = None

    def stop_current_scan(self):
        """Stop the current scan and clean up."""
        try:
            # Stop the scan worker
            if self.scan_worker and self.scan_worker.isRunning():
                if hasattr(self.scan_worker, 'tools'):
                    self.scan_worker.tools.stop_current_scan()
                self.scan_worker.terminate()
                self.scan_worker.wait()
            
            # Update UI elements
            self.subdomain_scan_btn.setEnabled(True)
            self.subdomain_stop_btn.setEnabled(False)
            self.subdomain_status_label.setText("Status: Scan stopped")
            
            self.port_scan_btn.setEnabled(True)
            self.port_stop_btn.setEnabled(False)
            self.port_status_label.setText("Status: Scan stopped")
            
            self.fuzzer_scan_btn.setEnabled(True)
            self.fuzzer_stop_btn.setEnabled(False)
            self.fuzzer_status_label.setText("Status: Scan stopped")
            
            self.vuln_scan_btn.setEnabled(True)
            self.vuln_stop_btn.setEnabled(False)
            self.vuln_status_label.setText("Status: Scan stopped")
            
            # Clean up the scan worker
            self.cleanup_scan_worker()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error stopping scan: {str(e)}")

    def closeEvent(self, event):
        """Handle application close event."""
        # Clean up any running scan
        self.cleanup_scan_worker()
        
        # Clean up proxy if running
        if self.proxy.is_running:
            self.proxy.stop()
        
        event.accept() 