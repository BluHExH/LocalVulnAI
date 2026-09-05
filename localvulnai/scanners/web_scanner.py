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

        headers = {k.lower(): v for k, v in response.headers.items()}

        if "content-security-policy" not in headers:
            findings.append(
                Finding(
                    title="Missing Content-Security-Policy header",
                    severity=Severity.MEDIUM,
                    description="No Content-Security-Policy header present.",
                    location=self.url,
                    recommendation="Add a strict CSP header to mitigate XSS and injection attacks.",
                    cwe="CWE-693",
                )
            )

        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(
                Finding(
                    title="Missing Clickjacking protection",
                    severity=Severity.MEDIUM,
                    description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
                    location=self.url,
                    recommendation="Set X-Frame-Options: DENY or use CSP frame-ancestors 'none'.",
                    cwe="CWE-1021",
                )
            )

        if self.url.startswith("https") and "strict-transport-security" not in headers:
            findings.append(
                Finding(
                    title="Missing HSTS header",
                    severity=Severity.LOW,
                    description="Strict-Transport-Security header is missing on an HTTPS site.",
                    location=self.url,
                    recommendation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    cwe="CWE-319",
                )
            )

        if "x-content-type-options" not in headers:
            findings.append(
                Finding(
                    title="Missing X-Content-Type-Options",
                    severity=Severity.LOW,
                    description="X-Content-Type-Options header is not set (should be nosniff).",
                    location=self.url,
                    recommendation="Add X-Content-Type-Options: nosniff",
                    cwe="CWE-16",
                )
            )

        if "referrer-policy" not in headers:
            findings.append(
                Finding(
                    title="Missing Referrer-Policy",
                    severity=Severity.INFO,
                    description="Referrer-Policy header is not set.",
                    location=self.url,
                    recommendation="Add Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
                )
            )

        if "permissions-policy" not in headers and "feature-policy" not in headers:
            findings.append(
                Finding(
                    title="Missing Permissions-Policy",
                    severity=Severity.INFO,
                    description="Permissions-Policy header is not present.",
                    location=self.url,
                    recommendation="Consider adding a Permissions-Policy to restrict browser features.",
                )
            )

        server = headers.get("server")
        if server:
            findings.append(
                Finding(
                    title="Server header information disclosure",
                    severity=Severity.INFO,
                    description=f"Server header reveals technology: {server}",
                    location=self.url,
                    recommendation="Remove or obfuscate the Server header.",
                    evidence=server,
                )
            )

        powered = headers.get("x-powered-by")
        if powered:
            findings.append(
                Finding(
                    title="X-Powered-By information disclosure",
                    severity=Severity.INFO,
                    description=f"X-Powered-By header reveals: {powered}",
                    location=self.url,
                    recommendation="Remove the X-Powered-By header.",
                    evidence=powered,
                )
            )

        raw_cookie = response.headers.get("set-cookie")
        set_cookie = [raw_cookie] if raw_cookie else []

        for cookie in set_cookie:
            cookie_l = cookie.lower()
            if "secure" not in cookie_l and self.url.startswith("https"):
                findings.append(
                    Finding(
                        title="Cookie without Secure flag",
                        severity=Severity.MEDIUM,
                        description="A Set-Cookie header is missing the Secure flag on HTTPS.",
                        location=self.url,
                        recommendation="Add the Secure flag to cookies.",
                        evidence=cookie[:120],
                        cwe="CWE-614",
                    )
                )
            if "httponly" not in cookie_l:
                findings.append(
                    Finding(
                        title="Cookie without HttpOnly flag",
                        severity=Severity.MEDIUM,
                        description="A Set-Cookie header is missing the HttpOnly flag.",
                        location=self.url,
                        recommendation="Add the HttpOnly flag to cookies that do not need JS access.",
                        evidence=cookie[:120],
                        cwe="CWE-1004",
                    )
                )

        return findings
