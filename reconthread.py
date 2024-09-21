from PyQt5.QtCore import pyqtSignal, QObject, QThread
from bugbountyrecon import BugBountyRecon
import logging
from concurrent.futures import ThreadPoolExecutor
import asyncio
import sys

class LogHandler(logging.Handler, QObject):
    log_message = pyqtSignal(str)

    def __init__(self):
        logging.Handler.__init__(self)
        QObject.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.log_message.emit(msg)

class ReconThread(QThread):
    update_status = pyqtSignal(str)
    update_results = pyqtSignal(str)
    update_log = pyqtSignal(str)
    update_progress = pyqtSignal(int)  # Add this line
    scan_complete = pyqtSignal(list)

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url
        self.setup_logging()

    def setup_logging(self):
        logger = logging.getLogger('bugbountyrecon')
        logger.setLevel(logging.DEBUG)
        handler = LogHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        handler.log_message.connect(self.update_log)
        logger.addHandler(handler)

    def run(self):
        self.update_status.emit("Initializing scan...")
        recon = BugBountyRecon(self.target_url)
        recon.progress_callback = self.update_progress.emit  # Add this line

        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        findings = loop.run_until_complete(recon.run())
        loop.close()

        for finding in findings:
            self.update_results.emit(finding)
        self.update_status.emit("Scan complete!")
        self.scan_complete.emit(findings)