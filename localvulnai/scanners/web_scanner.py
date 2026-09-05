from typing import List
import httpx
from localvulnai.scanners.base import BaseScanner
from localvulnai.models.finding import Finding, Severity


class WebScanner(BaseScanner):
    def __init__(self, url: str):
        self.url = url.rstrip("/")

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        try:
            with httpx.Client(timeout=15.0, follow_redirects=True) as client:
                response = client.get(self.url)
        except Exception as e:
            findings.append(
                Finding(
                    title="Could not reach target",
                    severity=Severity.INFO,
                    description=f"Failed to connect: {e}",
                    location=self.url,
                )
            )
            return findings

        # Basic security header checks
        headers = {k.lower(): v for k, v in response.headers.items()}

        if "content-security-policy" not in headers:
            findings.append(
                Finding(
                    title="Missing Content-Security-Policy header",
                    severity=Severity.MEDIUM,
                    description="The response does not include a Content-Security-Policy header.",
                    location=self.url,
                    recommendation="Add a strict CSP header to mitigate XSS and data injection attacks.",
                )
            )

        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append(
                Finding(
                    title="Missing X-Frame-Options / frame-ancestors",
                    severity=Severity.MEDIUM,
                    description="Clickjacking protection appears to be missing.",
                    location=self.url,
                    recommendation="Set X-Frame-Options: DENY or use CSP frame-ancestors.",
                )
            )

        if "strict-transport-security" not in headers and self.url.startswith("https"):
            findings.append(
                Finding(
                    title="Missing HSTS header",
                    severity=Severity.LOW,
                    description="Strict-Transport-Security header is not present.",
                    location=self.url,
                    recommendation="Add Strict-Transport-Security header for HTTPS sites.",
                )
            )

        server = headers.get("server")
        if server:
            findings.append(
                Finding(
                    title="Server header information disclosure",
                    severity=Severity.INFO,
                    description=f"Server header reveals: {server}",
                    location=self.url,
                    recommendation="Consider removing or obfuscating the Server header.",
                    evidence=server,
                )
            )

        return findings
