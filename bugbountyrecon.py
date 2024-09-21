import requests 
import re
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
import subprocess
import logging
import time
import yaml
import asyncio
import aiohttp
from functools import lru_cache
from aiohttp import ClientSession, ClientError
from typing import Dict, Any, Tuple, List

class BugBountyRecon:

    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.visited_urls = set()
        self.findings = []
        self.logger = logging.getLogger(__name__)
        self.total_tasks = 6  # Number of main tasks
        self.completed_tasks = 0
        self.request_delay = 0.5  # 500ms delay between requests
        with open('config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        self.headers = {'User-Agent': self.config['scan']['user_agent']}
        self.progress_callback = None

    @lru_cache(maxsize=100)
    async def fetch_url(self, url: str) -> tuple[str, Dict[str, Any]]:
        async with ClientSession() as session:
            try:
                async with session.get(url, allow_redirects=False) as response:
                    content = await response.text()
                    headers = dict(response.headers)  # Convert headers to a regular dictionary
                    return content, headers
            except ClientError as e:
                self.logger.error(f"Error fetching {url}: {str(e)}")
                return "", {}

    async def crawl(self, url: str, depth: int = 0) -> None:
        if depth >= self.config['scan']['max_depth'] or len(self.visited_urls) >= self.config['scan']['max_urls']:
            return
        if url in self.visited_urls or not url.startswith(self.target_url):
            return
        self.visited_urls.add(url)
        self.logger.info(f"Crawling: {url}")
        try:
            content, headers = await self.fetch_url(url)
            if not content and not headers:
                self.logger.warning(f"No content or headers returned for {url}")
                return
            content_type = headers.get('Content-Type', '')
            if 'text/html' in content_type:
                # Convert headers to a tuple of frozensets
                headers_tuple = tuple(frozenset(headers.items()))
                await self.check_vulnerabilities(url, headers_tuple, content)
                links = re.findall(r'href=[\'"]?([^\'" >]+)', content)
                tasks = []
                for link in links:
                    full_url = urljoin(url, link)
                    if full_url not in self.visited_urls:
                        tasks.append(asyncio.create_task(self.crawl(full_url, depth + 1)))
                await asyncio.gather(*tasks)
            else:
                self.logger.info(f"Skipping non-HTML content at {url}")
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")

    @lru_cache(maxsize=100)
    async def check_vulnerabilities(self, url: str, headers: tuple, content: str):
        # Convert the tuple of frozensets back to a dictionary
        headers_dict = dict(item for subset in headers for item in subset)
        await asyncio.gather(
            self.check_headers(url, headers_dict),
            self.check_comments(url, content),
            self.check_hidden_inputs(url, content),
            self.check_file_inclusion(url),
            self.check_cors(url),
            self.check_clickjacking(url),
            self.check_open_redirects(url),
            self.check_xss(url),
            self.check_sqli(url)
        )

    @lru_cache(maxsize=100)
    async def check_headers(self, url, headers):
        interesting_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
        for header in interesting_headers:
            if header in headers:
                self.findings.append(f"Interesting header found at {url}: {header}: {headers[header]}")

    @lru_cache(maxsize=100)
    async def check_comments(self, url, content):
        comments = re.findall(r'<!--(.*)-->', content)
        if comments:
            self.findings.append(f"HTML comments found at {url}. Might contain sensitive information.")

    @lru_cache(maxsize=100)
    async def check_hidden_inputs(self, url, content):
        hidden_inputs = re.findall(r'<input[^>]*type=[\'"]hidden[\'"][^>]*>', content)
        if hidden_inputs:
            self.findings.append(f"Hidden input fields found at {url}. Check for sensitive data.")

    @lru_cache(maxsize=100)
    async def check_file_inclusion(self, url):
        lfi_payloads = ['../../../etc/passwd', '..%2f..%2f..%2fetc%2fpasswd']
        for payload in lfi_payloads:
            test_url = f"{url}?file={payload}"
            try:
                content, _ = await self.fetch_url(test_url)
                if "root:x:" in content:
                    self.findings.append(f"Potential Local File Inclusion vulnerability found at {test_url}")
                    break
            except aiohttp.ClientError:
                pass

    @lru_cache(maxsize=100)
    async def check_cors(self, url):
        headers = {'Origin': 'https://evil.com'}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    acao_header = response.headers.get('Access-Control-Allow-Origin')
                    if acao_header == '*' or acao_header == 'https://evil.com':
                        self.findings.append(f"Potential CORS misconfiguration at {url}")
        except aiohttp.ClientError:
            pass

    @lru_cache(maxsize=100)
    async def check_clickjacking(self, url):
        try:
            _, headers = await self.fetch_url(url)
            x_frame_options = headers.get('X-Frame-Options')
            csp = headers.get('Content-Security-Policy')
            if not x_frame_options and not csp:
                self.findings.append(f"Potential Clickjacking vulnerability at {url}")
        except aiohttp.ClientError:
            pass

    @lru_cache(maxsize=100)
    async def check_open_redirects(self, url):
        # Implement this method
        pass

    @lru_cache(maxsize=100)
    async def check_xss(self, url):
        # Implement this method
        pass

    @lru_cache(maxsize=100)
    async def check_sqli(self, url):
        # Implement this method
        pass

    @lru_cache(maxsize=1)
    async def check_robots_txt(self):
        robots_url = urljoin(self.target_url, '/robots.txt')
        try:
            content, _ = await self.fetch_url(robots_url)
            if content:
                self.findings.append(f"robots.txt found. Check for interesting paths: {robots_url}")
        except aiohttp.ClientError:
            pass

    @lru_cache(maxsize=1)
    async def check_ssl(self):
        try:
            hostname = self.domain
            context = ssl.create_default_context()
            conn = asyncio.open_connection(hostname, 443, ssl=context)
            _, writer = await asyncio.wait_for(conn, timeout=5.0)
            writer.close()
            await writer.wait_closed()
            self.findings.append(f"SSL is available for {hostname}")
        except Exception as e:
            self.findings.append(f"SSL error: {str(e)}")

    @lru_cache(maxsize=1)
    async def scan_ports(self):
        common_ports = [21, 22, 80, 443, 8080, 8443]
        open_ports = []
        
        async def check_port(port):
            try:
                conn = asyncio.open_connection(self.domain, port)
                await asyncio.wait_for(conn, timeout=1.0)
                open_ports.append(port)
            except (asyncio.TimeoutError, ConnectionRefusedError):
                pass

        await asyncio.gather(*[check_port(port) for port in common_ports])
        
        if open_ports:
            self.findings.append(f"Open ports found: {', '.join(map(str, open_ports))}")

    async def check_subdomain_takeover(self):
        # Implement this method if needed, or remove it from the run method
        pass

    async def run_nuclei(self):
        # This method should be implemented as an async method
        # For now, we'll just pass
        pass

    async def run(self):
        self.logger.info("Starting reconnaissance")
        tasks = [
            self.check_robots_txt(),
            self.check_ssl(),
            self.crawl(self.target_url),
            self.scan_ports(),
            self.check_subdomain_takeover(),
            self.run_nuclei()
        ]
        await asyncio.gather(*tasks)
        self.logger.info("Reconnaissance completed")
        return self.findings

    def make_request(self, url, method='get', **kwargs):
        kwargs.setdefault('headers', self.headers)
        kwargs.setdefault('timeout', self.config['scan']['timeout'])
        time.sleep(self.request_delay)
        return requests.request(method, url, **kwargs)

    def update_progress(self):
        self.completed_tasks += 1
        progress = int((self.completed_tasks / self.total_tasks) * 100)
        if self.progress_callback:
            self.progress_callback(progress)