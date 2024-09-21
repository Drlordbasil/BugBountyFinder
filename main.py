import sys
import os
import requests
import re
import json  # Add this line
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import socket
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QTextEdit, QLabel, QLineEdit, QFrame, QComboBox, QProgressBar, QTabWidget,
                             QStyleFactory, QMessageBox, QFileDialog, QTableWidget, QTableWidgetItem)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QSettings
from PyQt5.QtGui import QPainter, QColor, QPen, QFont
from groq import Groq

from bugbountyrecon import BugBountyRecon
from loadingspinner import LoadingSpinner

from reconthread import ReconThread
from reportgenerationthread import ReportGenerationThread

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bug Bounty Recon Tool")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QLabel, QTextEdit, QLineEdit, QPushButton, QComboBox, QProgressBar {
                font-size: 14px;
            }
            QPushButton {
                background-color: #4a4a4a;
                color: #ffffff;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5a5a5a;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #3a3a3a;
                color: #ffffff;
                border: 1px solid #5a5a5a;
                border-radius: 4px;
                padding: 4px;
            }
            QProgressBar {
                border: 2px solid #5a5a5a;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #3daee9;
                width: 10px;
                margin: 0.5px;
            }
        """)
        self.settings = QSettings("BugBountyRecon", "Settings")
        self.findings_categories = {
            "XSS": 0,
            "SQL Injection": 0,
            "CSRF": 0,
            "Open Redirect": 0,
            "Information Disclosure": 0,
            "Configuration Issue": 0,
            "Other": 0
        }
        self.initUI()
        self.load_settings()

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Header
        header_layout = QHBoxLayout()
        logo_label = QLabel("🕵️")
        logo_label.setFont(QFont("Arial", 24))
        header_layout.addWidget(logo_label)
        title_label = QLabel("Bug Bounty Recon Tool")
        title_label.setFont(QFont("Arial", 20, QFont.Bold))
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        main_layout.addLayout(header_layout)

        # URL input and scan button
        url_layout = QHBoxLayout()
        url_label = QLabel("Target URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL (e.g., https://example.com)")
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(self.scan_button)
        main_layout.addLayout(url_layout)

        # Status and progress
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready to scan")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)
        main_layout.addLayout(status_layout)

        # Spinner
        self.spinner = LoadingSpinner(self, size=50, line_width=5, color=QColor(61, 174, 233), speed=30)
        self.spinner.setFixedSize(50, 50)
        self.spinner.hide()
        spinner_layout = QHBoxLayout()
        spinner_layout.addWidget(self.spinner, alignment=Qt.AlignCenter)
        main_layout.addLayout(spinner_layout)

        # Tabs for results, logs, and report
        self.tab_widget = QTabWidget()

        # Modify the Findings tab
        findings_widget = QWidget()
        findings_layout = QVBoxLayout(findings_widget)
        
        self.findings_table = QTableWidget(len(self.findings_categories), 3)
        self.findings_table.setHorizontalHeaderLabels(["Category", "Count", "Severity"])
        self.update_findings_table()
        findings_layout.addWidget(self.findings_table)

        self.grade_label = QLabel("Overall Grade: N/A")
        findings_layout.addWidget(self.grade_label)

        self.difficulty_label = QLabel("Difficulty: N/A")
        findings_layout.addWidget(self.difficulty_label)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        findings_layout.addWidget(self.results_text)

        self.tab_widget.addTab(findings_widget, "Findings")

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        self.tab_widget.addTab(self.log_text, "Logs")
        self.tab_widget.addTab(self.report_text, "Report")
        main_layout.addWidget(self.tab_widget)

        # Findings count and report generation
        bottom_layout = QHBoxLayout()
        self.findings_count_label = QLabel("Findings: 0")
        bottom_layout.addWidget(self.findings_count_label)
        bottom_layout.addStretch()
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["Low", "Medium", "High", "Critical"])
        bottom_layout.addWidget(QLabel("Severity:"))
        bottom_layout.addWidget(self.severity_combo)
        self.generate_report_button = QPushButton("Generate Report")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.generate_report_button.setEnabled(False)
        bottom_layout.addWidget(self.generate_report_button)
        self.save_report_button = QPushButton("Save Report")
        self.save_report_button.clicked.connect(self.save_report)
        self.save_report_button.setEnabled(False)
        bottom_layout.addWidget(self.save_report_button)
        main_layout.addLayout(bottom_layout)

        # Add a menu bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu('File')
        settings_action = file_menu.addAction('Settings')
        settings_action.triggered.connect(self.open_settings)
        export_action = file_menu.addAction('Export Findings')
        export_action.triggered.connect(self.export_findings)

    def open_settings(self):
        # Implement a settings dialog
        pass

    def export_findings(self):
        if hasattr(self, 'findings'):
            file_name, _ = QFileDialog.getSaveFileName(self, "Save Findings", "", "JSON Files (*.json)")
            if file_name:
                with open(file_name, 'w') as f:
                    json.dump(self.findings, f, indent=4)
                QMessageBox.information(self, "Export Successful", f"Findings exported to {file_name}")
        else:
            QMessageBox.warning(self, "No Findings", "No findings to export. Please run a scan first.")

    def load_settings(self):
        if hasattr(self, 'url_input'):
            self.url_input.setText(self.settings.value("last_url", ""))

    def save_settings(self):
        if hasattr(self, 'url_input'):
            self.settings.setValue("last_url", self.url_input.text())

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)

    def start_scan(self):
        self.results_text.clear()
        self.log_text.clear()
        self.report_text.clear()
        self.findings_count_label.setText("Findings: 0")
        self.generate_report_button.setEnabled(False)
        self.save_report_button.setEnabled(False)
        target_url = self.url_input.text()
        if not target_url.startswith(('http://', 'https://')):
            self.status_label.setText("Invalid URL. Please include http:// or https://")
            return
        self.scan_thread = ReconThread(target_url)
        self.scan_thread.update_status.connect(self.update_status)
        self.scan_thread.update_results.connect(self.update_results)
        self.scan_thread.update_log.connect(self.update_log)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.scan_complete.connect(self.scan_complete)
        self.scan_thread.start()
        self.scan_button.setEnabled(False)
        self.spinner.show()
        self.progress_bar.setValue(0)

    def update_status(self, status):
        self.status_label.setText(status)

    def update_results(self, finding):
        self.results_text.append(finding)
        category, severity = self.categorize_finding(finding)
        self.findings_categories[category] += 1
        
        self.update_findings_table()
        self.update_grade()

        count = sum(self.findings_categories.values())
        self.findings_count_label.setText(f"Findings: {count}")

    def categorize_finding(self, finding):
        # This is a simple categorization. You might want to implement a more sophisticated system.
        if "XSS" in finding:
            return "XSS", "High"
        elif "SQL" in finding:
            return "SQL Injection", "Critical"
        elif "CSRF" in finding:
            return "CSRF", "Medium"
        elif "redirect" in finding.lower():
            return "Open Redirect", "Low"
        elif "information" in finding.lower():
            return "Information Disclosure", "Medium"
        elif "configuration" in finding.lower():
            return "Configuration Issue", "Low"
        else:
            return "Other", "Low"

    def update_findings_table(self):
        for row, (category, count) in enumerate(self.findings_categories.items()):
            self.findings_table.setItem(row, 0, QTableWidgetItem(category))
            self.findings_table.setItem(row, 1, QTableWidgetItem(str(count)))
            severity = self.get_category_severity(category)
            self.findings_table.setItem(row, 2, QTableWidgetItem(severity))
        self.findings_table.resizeColumnsToContents()

    def get_category_severity(self, category):
        # This is a simple mapping. You might want to implement a more sophisticated system.
        severity_map = {
            "XSS": "High",
            "SQL Injection": "Critical",
            "CSRF": "Medium",
            "Open Redirect": "Low",
            "Information Disclosure": "Medium",
            "Configuration Issue": "Low",
            "Other": "Low"
        }
        return severity_map.get(category, "Low")

    def update_grade(self):
        total_checked = getattr(self, 'total_checked', 0)
        if total_checked > 0:
            error_free = total_checked - sum(self.findings_categories.values())
            grade = (error_free / total_checked) * 100
            self.grade_label.setText(f"Overall Grade: {grade:.2f}%")
            self.assess_difficulty(grade)

    def assess_difficulty(self, grade):
        if grade >= 90:
            difficulty = "Hard"
        elif grade >= 70:
            difficulty = "Medium"
        else:
            difficulty = "Easy"
        self.difficulty_label.setText(f"Difficulty: {difficulty}")

    def update_log(self, message):
        self.log_text.append(message)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def scan_complete(self, findings):
        self.scan_button.setEnabled(True)
        self.spinner.hide()
        self.findings = findings
        self.generate_report_button.setEnabled(True)
        self.status_label.setText("Scan complete!")

    def generate_report(self):
        self.report_text.clear()
        self.report_text.append("Generating report...")
        self.generate_report_button.setEnabled(False)
        self.report_thread = ReportGenerationThread(self.findings, self.url_input.text(), 
                                                    self.severity_combo.currentText(), 
                                                    self.findings_categories)
        self.report_thread.report_complete.connect(self.display_report)
        self.report_thread.start()

    def display_report(self, report):
        self.report_text.clear()
        self.report_text.append(report)
        self.generate_report_button.setEnabled(True)
        self.save_report_button.setEnabled(True)
        self.tab_widget.setCurrentIndex(2)  # Switch to the Report tab

    def save_report(self):
        with open("bug_bounty_report.txt", "w") as f:
            f.write(self.report_text.toPlainText())
        self.status_label.setText("Report saved to bug_bounty_report.txt")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())