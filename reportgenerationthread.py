from PyQt5.QtCore import pyqtSignal, QThread  # Or use PySide2.QtCore if you're using PySide2
from groq import Groq
import os

class ReportGenerationThread(QThread):
    report_complete = pyqtSignal(str)


    def __init__(self, findings, target_url, severity):
        QThread.__init__(self)
        self.findings = findings
        self.target_url = target_url
        self.severity = severity

    def run(self):
        client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        findings_text = "\n".join(self.findings)
        prompt = f"""Generate a bug bounty report for HackerOne based on the following findings:

Target URL: {self.target_url}
Severity: {self.severity}

Findings:
{findings_text}

Format the report with the following sections:
1. Title
2. Description
3. Steps to Reproduce
4. Impact
5. Remediation

Ensure the report is professional, detailed, and follows best practices for bug bounty submissions."""

        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama3-8b-8192",
        )
        report = chat_completion.choices[0].message.content
        self.report_complete.emit(report)