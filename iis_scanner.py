#!/usr/bin/env python3
"""
IIS Web Vulnerability Scanner
Checks for common IIS misconfigurations and vulnerabilities.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

VERSION = "1.0.0"

BANNER = r"""
  ___ ___ ___   ___
 |_ _|_ _/ __| / __| __ __ _ _ _  _ _  ___ _ _
  | | | |\__ \ \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |___|___|___/ |___/\__\__,_|_||_|_||_\___|_|
"""

# ── RFC-1918 / loopback pattern ────────────────────────────────────────────────
PRIVATE_IP_RE = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r')\b'
)

# ── Security headers that should be present ────────────────────────────────────
REQUIRED_SECURITY_HEADERS = {
    "X-Frame-Options":           "Prevents clickjacking. Set to DENY or SAMEORIGIN.",
    "X-Content-Type-Options":    "Prevents MIME-type sniffing. Set to nosniff.",
    "Content-Security-Policy":   "Defines allowed content sources.",
    "Strict-Transport-Security": "Enforces HTTPS (HSTS).",
    "Referrer-Policy":           "Controls referrer info in requests.",
    "Permissions-Policy":        "Restricts access to browser features.",
}

# ── IIS / ASP.NET information-disclosure headers ───────────────────────────────
INFO_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "X-Version",
]

# ── Sensitive paths to probe ───────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ("elmah.axd",               "ELMAH error log viewer",          "HIGH"),
    ("trace.axd",               "ASP.NET Trace Viewer",            "HIGH"),
    ("ScriptResource.axd",      "Script resource handler",         "LOW"),
    ("WebResource.axd",         "Web resource handler",            "LOW"),
    ("_vti_bin/shtml.exe",      "FrontPage Server Extensions",     "HIGH"),
    ("_vti_bin/_vti_aut/author.dll", "FrontPage authoring DLL",    "HIGH"),
    ("_vti_pvt/service.pwd",    "FrontPage password file",         "CRITICAL"),
    ("web.config",              "ASP.NET configuration file",      "CRITICAL"),
    ("app.config",              "Application configuration file",  "HIGH"),
    ("robots.txt",              "Robots exclusion file",           "INFO"),
    (".git/HEAD",               "Git repository exposed",          "CRITICAL"),
    (".svn/entries",            "SVN repository exposed",          "CRITICAL"),
    ("iisstart.htm",            "Default IIS start page",          "LOW"),
]

# ── Dangerous HTTP methods ─────────────────────────────────────────────────────
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "PROPFIND", "PROPPATCH",
                     "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]


# ═══════════════════════════════════════════════════════════════════════════════
# Data model
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    name: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO | PASS
    status: str              # VULNERABLE | PASS | INFO | ERROR
    detail: str
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Output helpers
# ═══════════════════════════════════════════════════════════════════════════════

SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "bold blue",
    "PASS":     "bold green",
}

STATUS_ICON = {
    "VULNERABLE": "✘",
    "PASS":       "✔",
    "INFO":       "ℹ",
    "ERROR":      "⚠",
}


def print_section(title: str):
    console.print()
    console.rule(f"[bold white]{title}[/bold white]", style="dim white")


def print_finding(f: Finding):
    style  = SEV_STYLE.get(f.severity, "white")
    icon   = STATUS_ICON.get(f.status, "?")
    sev_badge = f"[{style}][{f.severity}][/{style}]"
    status_colour = "red" if f.status == "VULNERABLE" else \
                    "green" if f.status == "PASS" else "blue"
    console.print(f"  [{status_colour}]{icon}[/{status_colour}] {sev_badge} {f.detail}")
    for ev in f.evidence:
        console.print(f"      [dim]{ev}[/dim]")
    if f.recommendation and f.status == "VULNERABLE":
        console.print(f"      [italic yellow]↳ {f.recommendation}[/italic yellow]")


def print_summary(findings: List[Finding]):
    console.print()
    console.rule("[bold white]Scan Summary[/bold white]", style="dim white")
    console.print()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "PASS": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold white",
                title="[bold]Findings by Severity[/bold]")
    tbl.add_column("Severity",  style="bold", width=12)
    tbl.add_column("Count",     justify="center", width=8)

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
    for sev in order:
        style = SEV_STYLE.get(sev, "white")
        tbl.add_row(f"[{style}]{sev}[/{style}]", str(counts[sev]))

    console.print(tbl)
    console.print()

    vuln = [f for f in findings if f.status == "VULNERABLE"]
    if vuln:
        tbl2 = Table(box=box.SIMPLE, show_header=True, header_style="bold white",
                     title="[bold red]Vulnerable Findings[/bold red]")
        tbl2.add_column("Check",          style="bold", min_width=36)
        tbl2.add_column("Severity",       width=10)
        tbl2.add_column("Detail",         min_width=42)
        for f in vuln:
            style = SEV_STYLE.get(f.severity, "white")
            tbl2.add_row(f.name,
                         f"[{style}]{f.severity}[/{style}]",
                         f.detail)
        console.print(tbl2)


# ═══════════════════════════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════════════════════════

class IISScanner:

    def __init__(self, url: str, verify_ssl: bool = False,
                 timeout: int = 10, proxy: Optional[str] = None,
                 user_agent: Optional[str] = None,
                 shortscan_path: Optional[str] = None):

        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        self.base_url      = url.rstrip("/")
        self.timeout       = timeout
        self.verify_ssl    = verify_ssl
        self.findings: List[Finding] = []
        self.shortscan_path = shortscan_path

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent":      user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self._base_resp: Optional[requests.Response] = None

    # ── HTTP helpers ────────────────────────────────────────────────────────────

    def _get(self, path: str = "", **kwargs) -> Optional[requests.Response]:
        url = (urljoin(self.base_url + "/", path.lstrip("/"))
               if path else self.base_url)
        try:
            return self.session.get(url, verify=self.verify_ssl,
                                    timeout=self.timeout, **kwargs)
        except Exception:
            return None

    def _request(self, method: str, path: str = "", **kwargs) -> Optional[requests.Response]:
        url = (urljoin(self.base_url + "/", path.lstrip("/"))
               if path else self.base_url)
        try:
            return self.session.request(method, url, verify=self.verify_ssl,
                                        timeout=self.timeout, **kwargs)
        except Exception:
            return None

    def _add(self, f: Finding):
        self.findings.append(f)
        print_finding(f)

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 1 – Server Banner / Information-disclosure headers
    # ══════════════════════════════════════════════════════════════════════════

    def check_server_banner(self):
        print_section("CHECK 1 – Server Banner & Information-disclosure Headers")

        resp = self._get(allow_redirects=True)
        if resp is None:
            self._add(Finding("Server Banner", "ERROR", "ERROR",
                               "Could not connect to target."))
            return
        self._base_resp = resp

        found_any = False
        for header in INFO_HEADERS:
            value = resp.headers.get(header)
            if value:
                found_any = True
                self._add(Finding(
                    name=f"Header: {header}",
                    severity="MEDIUM",
                    status="VULNERABLE",
                    detail=f"Header '{header}' discloses server information.",
                    evidence=[f"{header}: {value}"],
                    recommendation=f"Remove or obscure the '{header}' response header.",
                ))

        # IIS-specific version string in Server header
        server = resp.headers.get("Server", "")
        if re.search(r"Microsoft-IIS/\d", server, re.IGNORECASE):
            self._add(Finding(
                name="IIS Version in Server header",
                severity="MEDIUM",
                status="VULNERABLE",
                detail="Server header exposes the IIS version number.",
                evidence=[f"Server: {server}"],
                recommendation=(
                    "Use URL Rewrite / web.config to remove the Server header, "
                    "or set it to a non-descriptive value."
                ),
            ))

        if not found_any:
            self._add(Finding("Server Banner", "PASS", "PASS",
                               "No information-disclosure headers detected."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 2 – Security Headers
    # ══════════════════════════════════════════════════════════════════════════

    def check_security_headers(self):
        print_section("CHECK 2 – Security Headers")

        resp = self._base_resp or self._get(allow_redirects=True)
        if resp is None:
            self._add(Finding("Security Headers", "ERROR", "ERROR",
                               "Could not connect to target."))
            return

        missing = []
        for header, desc in REQUIRED_SECURITY_HEADERS.items():
            if header.lower() not in {k.lower() for k in resp.headers}:
                missing.append((header, desc))

        for header, desc in missing:
            self._add(Finding(
                name=f"Missing: {header}",
                severity="MEDIUM",
                status="VULNERABLE",
                detail=f"Security header '{header}' is absent.",
                evidence=[f"Not present in: {resp.url}"],
                recommendation=desc,
            ))

        # X-XSS-Protection still checked: deprecated in modern browsers but
        # its presence with dangerous values (e.g. 1; mode=block via CDN) is noted.
        xxss = resp.headers.get("X-XSS-Protection", "")
        if xxss and xxss.strip() == "1":
            self._add(Finding(
                name="X-XSS-Protection weak value",
                severity="LOW",
                status="VULNERABLE",
                detail="X-XSS-Protection is set to '1' (report only). Prefer 'X-XSS-Protection: 0' "
                       "on modern stacks and rely on CSP instead.",
                evidence=[f"X-XSS-Protection: {xxss}"],
                recommendation="Set to '0' and implement a strong Content-Security-Policy.",
            ))

        if not missing:
            self._add(Finding("Security Headers", "PASS", "PASS",
                               "All required security headers are present."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 3 – Default IIS Page
    # ══════════════════════════════════════════════════════════════════════════

    def check_default_iis_page(self):
        print_section("CHECK 3 – Default IIS Welcome Page")

        resp = self._get(allow_redirects=True)
        if resp is None:
            self._add(Finding("Default IIS Page", "ERROR", "ERROR",
                               "Could not connect to target."))
            return

        body = resp.text.lower()
        iis_markers = [
            "iis windows server",
            "internet information services",
            "welcome to iis",
            "iisstart.htm",
            "iisstart.png",
        ]
        hits = [m for m in iis_markers if m in body]

        if hits:
            self._add(Finding(
                name="Default IIS Page",
                severity="LOW",
                status="VULNERABLE",
                detail="The default IIS welcome page is publicly accessible.",
                evidence=[f"Marker found: '{h}'" for h in hits],
                recommendation=(
                    "Replace the default content with application content "
                    "or restrict access to the root path."
                ),
            ))
        else:
            self._add(Finding("Default IIS Page", "PASS", "PASS",
                               "Default IIS welcome page not detected."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 4 – ASP.NET Version 4.0.30319
    # ══════════════════════════════════════════════════════════════════════════

    def check_aspnet_version_4(self):
        print_section("CHECK 4 – ASP.NET Version 4.0.30319 Disclosure")

        resp = self._base_resp or self._get(allow_redirects=True)
        if resp is None:
            self._add(Finding("ASP.NET v4.0.30319", "ERROR", "ERROR",
                               "Could not connect to target."))
            return

        version_header = resp.headers.get("X-AspNet-Version", "")
        if "4.0.30319" in version_header:
            self._add(Finding(
                name="ASP.NET Version 4.0.30319",
                severity="MEDIUM",
                status="VULNERABLE",
                detail="Server advertises ASP.NET version 4.0.30319 — a known-vulnerable runtime.",
                evidence=[f"X-AspNet-Version: {version_header}"],
                recommendation=(
                    "Upgrade to a supported ASP.NET version and suppress the "
                    "X-AspNet-Version header via <httpRuntime enableVersionHeader='false'/> "
                    "in web.config."
                ),
            ))
        elif version_header:
            self._add(Finding(
                name="ASP.NET Version Disclosed",
                severity="LOW",
                status="VULNERABLE",
                detail=f"ASP.NET version is disclosed (not 4.0.30319).",
                evidence=[f"X-AspNet-Version: {version_header}"],
                recommendation=(
                    "Suppress X-AspNet-Version via "
                    "<httpRuntime enableVersionHeader='false'/> in web.config."
                ),
            ))
        else:
            self._add(Finding("ASP.NET v4.0.30319", "PASS", "PASS",
                               "X-AspNet-Version header not present."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 5 – Verbose Error Pages (invalid .aspx)
    # ══════════════════════════════════════════════════════════════════════════

    def check_verbose_errors(self):
        print_section("CHECK 5 – Verbose Error Pages (invalid .aspx request)")

        resp = self._get("iisscanner_nonexistent_probe.aspx", allow_redirects=False)
        if resp is None:
            self._add(Finding("Verbose Error Pages", "ERROR", "ERROR",
                               "No response to error probe."))
            return

        body = resp.text
        body_lower = body.lower()

        indicators = {
            "Stack trace":             re.search(r'stack trace', body_lower),
            "ASP.NET version string":  re.search(r'asp\.net.*\d+\.\d+', body_lower),
            "Server OS path":          re.search(r'[cCdD]:\\', body),
            "Source file path":        re.search(r'(inetpub|wwwroot)', body_lower),
            "customErrors=Off hint":   re.search(r'customerrors\s*mode\s*=\s*["\']?off', body_lower),
            "Runtime version":         re.search(r'(\.net|clr)\s*[\d.]+', body_lower),
        }

        hits = {k: bool(v) for k, v in indicators.items() if v}

        if hits:
            self._add(Finding(
                name="Verbose ASP.NET Error Page",
                severity="MEDIUM",
                status="VULNERABLE",
                detail=f"Error page reveals internal details ({', '.join(hits.keys())}).",
                evidence=[f"HTTP {resp.status_code} → {resp.url}"]
                         + [f"  Indicator: {k}" for k in hits],
                recommendation=(
                    "Set <customErrors mode='On' defaultRedirect='error.htm'/> "
                    "in web.config and configure generic error pages in IIS."
                ),
            ))
        elif resp.status_code in (200, 500):
            self._add(Finding(
                name="Verbose ASP.NET Error Page",
                severity="LOW",
                status="VULNERABLE",
                detail=f"Server returned HTTP {resp.status_code} for a non-existent .aspx — "
                       f"may indicate custom error handling is disabled.",
                evidence=[f"HTTP {resp.status_code} for probe URL"],
                recommendation="Review custom error configuration in web.config.",
            ))
        else:
            self._add(Finding("Verbose Error Pages", "PASS", "PASS",
                               f"Server returned HTTP {resp.status_code} — "
                               f"no verbose detail detected."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 6 – trace.axd Information Leakage
    # ══════════════════════════════════════════════════════════════════════════

    def check_trace_axd(self):
        print_section("CHECK 6 – trace.axd Information Leakage")

        for path in ("trace.axd", "Trace.axd"):
            resp = self._get(path, allow_redirects=True)
            if resp is None:
                continue
            body_lower = resp.text.lower()

            if resp.status_code == 200 and (
                "application trace" in body_lower or
                "physical directory" in body_lower or
                "trace information" in body_lower or
                "request details" in body_lower
            ):
                self._add(Finding(
                    name="trace.axd Accessible",
                    severity="HIGH",
                    status="VULNERABLE",
                    detail="ASP.NET Trace Viewer (trace.axd) is publicly accessible — "
                           "exposes request details, session state, and server internals.",
                    evidence=[f"HTTP {resp.status_code} → {resp.url}"],
                    recommendation=(
                        "Disable tracing in web.config: "
                        "<trace enabled='false' localOnly='true'/> "
                        "and deny access in IIS to *.axd handlers."
                    ),
                ))
                return
            elif resp.status_code == 200:
                self._add(Finding(
                    name="trace.axd Returns 200",
                    severity="MEDIUM",
                    status="VULNERABLE",
                    detail="trace.axd returns HTTP 200 — confirm whether tracing is active.",
                    evidence=[f"HTTP {resp.status_code} → {resp.url}"],
                    recommendation="Disable or restrict trace.axd in IIS and web.config.",
                ))
                return

        self._add(Finding("trace.axd", "PASS", "PASS",
                           "trace.axd is not accessible."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 7 – Debug Mode Enabled
    # ══════════════════════════════════════════════════════════════════════════

    def check_debug_mode(self):
        print_section("CHECK 7 – Debug Mode Enabled")

        evidence = []

        # 7a – Error page debug indicators
        resp_err = self._get("iisscanner_debug_probe.aspx", allow_redirects=False)
        if resp_err:
            body = resp_err.text
            body_lower = body.lower()
            if re.search(r'compilation\s+debug\s*=\s*["\']true["\']', body_lower):
                evidence.append("Error page contains: compilation debug=\"true\"")
            if re.search(r'debug\s*=\s*["\']?true', body_lower):
                evidence.append("Error page references debug=true")
            if re.search(r'\.pdb', body_lower):
                evidence.append("Error page references .pdb debug symbols")

        # 7b – DEBUG HTTP verb
        resp_dbg = self._request("DEBUG", allow_redirects=False,
                                 headers={"Command": "stop-debug",
                                          "Accept": "application/x-msdeb"})
        if resp_dbg and resp_dbg.status_code not in (405, 501, 400, 403, 404):
            evidence.append(f"DEBUG verb returned HTTP {resp_dbg.status_code} "
                            f"(expected 405/501)")

        # 7c – X-HTTP-Method-Override: DEBUG
        resp_mo = self._request("POST", allow_redirects=False,
                                headers={"X-HTTP-Method-Override": "DEBUG"})
        if resp_mo and resp_mo.status_code not in (405, 501, 400, 403, 404, 200):
            evidence.append(f"X-HTTP-Method-Override: DEBUG returned HTTP {resp_mo.status_code}")

        if evidence:
            self._add(Finding(
                name="Debug Mode Indicators",
                severity="HIGH",
                status="VULNERABLE",
                detail="Debug mode indicators detected — may expose sensitive application details.",
                evidence=evidence,
                recommendation=(
                    "Set compilation debug=\"false\" in web.config "
                    "<compilation debug='false' targetFramework='4.x'/> "
                    "and disable HTTP DEBUG verb in IIS."
                ),
            ))
        else:
            self._add(Finding("Debug Mode", "PASS", "PASS",
                               "No debug mode indicators detected."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 8 – IIS Tilde Shortname Disclosure (shortscan)
    # ══════════════════════════════════════════════════════════════════════════

    def check_tilde_shortname(self):
        print_section("CHECK 8 – IIS Tilde (~) Shortname Disclosure")

        if not self.shortscan_path:
            self._add(Finding(
                name="Tilde Shortname (shortscan)",
                severity="INFO",
                status="INFO",
                detail="shortscan not found — skipping tilde enumeration.",
                recommendation=(
                    "Install shortscan: "
                    "go install github.com/bitquark/shortscan/cmd/shortscan@latest"
                ),
            ))
            return

        console.print(f"  [dim]Running shortscan against {self.base_url} …[/dim]")
        try:
            result = subprocess.run(
                [self.shortscan_path, self.base_url],
                capture_output=True, text=True, timeout=120
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            self._add(Finding("Tilde Shortname (shortscan)", "ERROR", "ERROR",
                               "shortscan timed out after 120 s."))
            return
        except Exception as exc:
            self._add(Finding("Tilde Shortname (shortscan)", "ERROR", "ERROR",
                               f"Failed to run shortscan: {exc}"))
            return

        console.print()
        # Print raw shortscan output verbatim (it has its own formatting)
        if output.strip():
            for line in output.strip().splitlines():
                console.print(f"  [dim]{line}[/dim]")
        console.print()

        # Parse shortscan results
        shortnames = re.findall(r'[A-Z0-9_\-~]{1,8}\.[A-Z0-9]{0,3}', output.upper())
        identified = re.search(r'Identified\s+(\d+)\s+item', output, re.IGNORECASE)
        count = int(identified.group(1)) if identified else 0

        if "vulnerable" in output.lower() or count > 0 or shortnames:
            self._add(Finding(
                name="Tilde Shortname Disclosure",
                severity="MEDIUM",
                status="VULNERABLE",
                detail=f"IIS tilde shortname enumeration possible — "
                       f"{count} item(s) identified.",
                evidence=([f"Shortnames found: {', '.join(set(shortnames[:10]))}"
                           ] if shortnames else [])
                         + ([f"shortscan: {identified.group(0)}"
                             ] if identified else []),
                recommendation=(
                    "Disable 8.3 filename generation: "
                    "fsutil behavior set disable8dot3 1 "
                    "and apply MS security guidance for IIS tilde vulnerability."
                ),
            ))
        elif "not vulnerable" in output.lower():
            self._add(Finding("Tilde Shortname Disclosure", "PASS", "PASS",
                               "shortscan reports target is not vulnerable."))
        else:
            self._add(Finding(
                name="Tilde Shortname Disclosure",
                severity="INFO",
                status="INFO",
                detail="shortscan completed — review raw output above for details.",
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 9 – CVE-2000-0649 Internal IP Address Disclosure
    # ══════════════════════════════════════════════════════════════════════════

    def check_internal_ip_disclosure(self):
        print_section("CHECK 9 – CVE-2000-0649: Internal IP Address Disclosure")

        evidence = []
        spoofed_host = "192.0.2.1"   # TEST-NET — not a real address

        # 9a – Spoof Host header and look for private IP in Location redirect
        try:
            resp = self.session.get(
                self.base_url,
                headers={"Host": spoofed_host},
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=False,
            )
            location = resp.headers.get("Location", "")
            if location:
                match = PRIVATE_IP_RE.search(location)
                if match:
                    evidence.append(
                        f"Location header contains private IP {match.group()} "
                        f"when Host: {spoofed_host} is used"
                    )
        except Exception:
            pass

        # 9b – Scan all headers of the normal response for private IPs
        resp_normal = self._base_resp or self._get(allow_redirects=True)
        if resp_normal:
            for hname, hval in resp_normal.headers.items():
                match = PRIVATE_IP_RE.search(hval)
                if match:
                    evidence.append(
                        f"Header '{hname}' contains private IP: {match.group()}"
                    )
            # 9c – Scan response body for private IPs (first 8 KB)
            body_sample = resp_normal.text[:8192]
            for match in PRIVATE_IP_RE.finditer(body_sample):
                ip = match.group()
                evidence.append(f"Response body contains private IP: {ip}")

        # Deduplicate
        evidence = list(dict.fromkeys(evidence))

        if evidence:
            self._add(Finding(
                name="CVE-2000-0649: Internal IP Disclosure",
                severity="MEDIUM",
                status="VULNERABLE",
                detail="Server discloses internal/private IP addresses.",
                evidence=evidence,
                recommendation=(
                    "Configure IIS to return generic or public-facing hostnames in "
                    "redirects. Ensure reverse-proxy headers (X-Forwarded-For, "
                    "X-Real-IP) are not echoed back, and suppress internal IP "
                    "addresses from response headers and bodies."
                ),
            ))
        else:
            self._add(Finding("CVE-2000-0649", "PASS", "PASS",
                               "No internal IP address disclosure detected."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 10 – Dangerous HTTP Methods & WebDAV
    # ══════════════════════════════════════════════════════════════════════════

    def check_http_methods(self):
        print_section("CHECK 10 – Dangerous HTTP Methods & WebDAV")

        resp_opts = self._request("OPTIONS", allow_redirects=False)
        if resp_opts is None:
            self._add(Finding("HTTP Methods", "ERROR", "ERROR",
                               "OPTIONS request failed."))
            return

        allowed_raw = (resp_opts.headers.get("Allow", "") + " " +
                       resp_opts.headers.get("Public", "") +
                       resp_opts.headers.get("MS-Author-Via", ""))
        allowed_upper = allowed_raw.upper()

        dangerous_found = [m for m in DANGEROUS_METHODS if m in allowed_upper]

        evidence = [f"Allow: {resp_opts.headers.get('Allow', '(not set)')}"]
        if resp_opts.headers.get("Public"):
            evidence.append(f"Public: {resp_opts.headers.get('Public')}")
        if resp_opts.headers.get("DAV"):
            evidence.append(f"DAV: {resp_opts.headers.get('DAV')}")
            evidence.append("WebDAV appears to be enabled.")

        # Also probe TRACE directly
        resp_trace = self._request("TRACE", allow_redirects=False,
                                   headers={"X-Scanner-Trace": "iisscanner-probe"})
        if resp_trace and resp_trace.status_code == 200:
            body_lower = resp_trace.text.lower()
            if "x-scanner-trace" in body_lower:
                dangerous_found.append("TRACE (confirmed XST)")
                evidence.append("TRACE method is active and reflects request headers "
                                 "(Cross-Site Tracing / XST risk).")

        if dangerous_found:
            webdav_methods = [m for m in dangerous_found
                              if m in ("PROPFIND","PROPPATCH","MKCOL",
                                       "COPY","MOVE","LOCK","UNLOCK")]
            severity = "HIGH" if webdav_methods or "PUT" in dangerous_found else "MEDIUM"
            self._add(Finding(
                name="Dangerous HTTP Methods",
                severity=severity,
                status="VULNERABLE",
                detail=f"Dangerous methods enabled: {', '.join(dangerous_found)}",
                evidence=evidence,
                recommendation=(
                    "Disable TRACE, TRACK and WebDAV methods in IIS if not required. "
                    "In IIS Manager → Request Filtering → HTTP Verbs, deny unwanted "
                    "verbs. Alternatively, add a <verbs> allow list in web.config."
                ),
            ))
        else:
            self._add(Finding("Dangerous HTTP Methods", "PASS", "PASS",
                               "No dangerous HTTP methods detected in OPTIONS response."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 11 – Directory Browsing / Listing
    # ══════════════════════════════════════════════════════════════════════════

    def check_directory_browsing(self):
        print_section("CHECK 11 – Directory Browsing / Listing")

        # Probe root and a few common directories
        paths_to_probe = ["", "images/", "css/", "js/", "assets/", "scripts/"]
        found = []

        for path in paths_to_probe:
            resp = self._get(path, allow_redirects=True)
            if resp is None:
                continue
            body_lower = resp.text.lower()
            if resp.status_code == 200 and (
                "directory listing for" in body_lower or
                "parent directory" in body_lower or
                ("<title>/" in body_lower) or
                ("index of /" in body_lower) or
                ("to parent directory" in body_lower)   # IIS style
            ):
                found.append(urljoin(self.base_url + "/", path))

        if found:
            self._add(Finding(
                name="Directory Browsing Enabled",
                severity="MEDIUM",
                status="VULNERABLE",
                detail="Directory listing is enabled — file system structure is exposed.",
                evidence=[f"Listing detected at: {u}" for u in found],
                recommendation=(
                    "Disable directory browsing in IIS Manager → "
                    "Directory Browsing → Disabled, or add "
                    "<directoryBrowse enabled='false'/> in web.config."
                ),
            ))
        else:
            self._add(Finding("Directory Browsing", "PASS", "PASS",
                               "No directory listing detected."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 12 – Sensitive File Exposure
    # ══════════════════════════════════════════════════════════════════════════

    def check_sensitive_files(self):
        print_section("CHECK 12 – Sensitive File & Path Exposure")

        found_any = False
        for path, description, severity in SENSITIVE_PATHS:
            resp = self._get(path, allow_redirects=False)
            if resp is None:
                continue

            accessible = False
            if resp.status_code == 200:
                accessible = True
            # Some IIS handlers return 302/301 to login — not exposed
            # Treat 403 as "exists but restricted" — still noteworthy for some paths
            elif resp.status_code == 403 and severity in ("CRITICAL", "HIGH"):
                accessible = True

            if accessible:
                found_any = True
                sev_display = severity if resp.status_code == 200 else "LOW"
                detail = (f"{description} is accessible (HTTP {resp.status_code})."
                          if resp.status_code == 200
                          else f"{description} exists but access is restricted "
                               f"(HTTP {resp.status_code}).")
                self._add(Finding(
                    name=f"Sensitive Path: /{path}",
                    severity=sev_display,
                    status="VULNERABLE",
                    detail=detail,
                    evidence=[f"HTTP {resp.status_code} → {resp.url}"],
                    recommendation=f"Remove or restrict access to '{path}'.",
                ))

        if not found_any:
            self._add(Finding("Sensitive Files", "PASS", "PASS",
                               "No sensitive files or paths exposed."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 13 – Microsoft-HTTPAPI Banner on 400 Errors
    # ══════════════════════════════════════════════════════════════════════════

    def check_httpapi_banner(self):
        print_section("CHECK 13 – Microsoft-HTTPAPI Banner (Malformed Request)")

        try:
            # Send a raw malformed HTTP/1.0 request — IIS kernel driver may respond
            # before the application layer and reveal the HTTPAPI version.
            import socket
            parsed = urlparse(self.base_url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            sock = socket.create_connection((host, port), timeout=self.timeout)
            sock.sendall(b"GET / HTTP/1.0\r\nHost: \r\n\r\n")
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
            sock.close()
            response_text = data.decode("utf-8", errors="replace")
        except Exception:
            # Fall back to requests
            resp = self._get(allow_redirects=False,
                             headers={"Host": ""})
            response_text = resp.text if resp else ""

        match = re.search(r"Microsoft-HTTPAPI/[\d.]+", response_text, re.IGNORECASE)
        if match:
            self._add(Finding(
                name="Microsoft-HTTPAPI Banner",
                severity="LOW",
                status="VULNERABLE",
                detail="Malformed request reveals Microsoft-HTTPAPI version in Server header.",
                evidence=[f"Detected: {match.group()}"],
                recommendation=(
                    "This is handled at the HTTP.sys kernel level. "
                    "Apply Windows updates and consider a WAF to mask version strings."
                ),
            ))
        else:
            self._add(Finding("Microsoft-HTTPAPI Banner", "PASS", "PASS",
                               "Microsoft-HTTPAPI banner not detected in error responses."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 14 – Cookie Security Flags
    # ══════════════════════════════════════════════════════════════════════════

    def check_cookie_security(self):
        print_section("CHECK 14 – Cookie Security Flags")

        resp = self._base_resp or self._get(allow_redirects=True)
        if resp is None or not resp.cookies:
            # Try common login/auth paths
            for path in ("login", "signin", "account/login", "user/login", "auth"):
                resp = self._get(path, allow_redirects=True)
                if resp and resp.cookies:
                    break

        if resp is None or not resp.cookies:
            self._add(Finding("Cookie Security", "INFO", "INFO",
                               "No cookies detected — unable to assess cookie flags."))
            return

        issues = []
        for cookie in resp.cookies:
            flags = []
            if not cookie.secure:
                flags.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("missing HttpOnly flag")
            samesite = cookie.get_nonstandard_attr("SameSite")
            if not samesite:
                flags.append("missing SameSite attribute")
            elif samesite.lower() == "none" and not cookie.secure:
                flags.append("SameSite=None without Secure")
            if flags:
                issues.append(f"Cookie '{cookie.name}': {', '.join(flags)}")

        if issues:
            self._add(Finding(
                name="Insecure Cookie Flags",
                severity="MEDIUM",
                status="VULNERABLE",
                detail=f"{len(issues)} cookie(s) with missing security flags.",
                evidence=issues,
                recommendation=(
                    "Set Secure, HttpOnly, and SameSite=Strict/Lax on all session "
                    "cookies via web.config <httpCookies httpOnlyCookies='true' "
                    "requireSSL='true'/> and application-level cookie options."
                ),
            ))
        else:
            self._add(Finding("Cookie Security", "PASS", "PASS",
                               "All detected cookies have appropriate security flags."))

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 15 – HTTP → HTTPS Redirect
    # ══════════════════════════════════════════════════════════════════════════

    def check_https_redirect(self):
        print_section("CHECK 15 – HTTP → HTTPS Redirect")

        parsed = urlparse(self.base_url)
        if parsed.scheme == "https":
            # Check that http:// version redirects
            http_url = self.base_url.replace("https://", "http://", 1)
        else:
            http_url = self.base_url

        try:
            resp = self.session.get(http_url, verify=False,
                                    timeout=self.timeout, allow_redirects=False)
        except Exception:
            self._add(Finding("HTTPS Redirect", "INFO", "INFO",
                               "Could not check HTTP → HTTPS redirect."))
            return

        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
            redir_type = "permanent" if resp.status_code in (301, 308) else "temporary"
            if resp.status_code in (302, 307):
                self._add(Finding(
                    name="HTTP → HTTPS Redirect (Temporary)",
                    severity="LOW",
                    status="VULNERABLE",
                    detail=f"HTTP redirects to HTTPS but uses a {redir_type} redirect "
                           f"(HTTP {resp.status_code}). Use 301 for SEO and security.",
                    evidence=[f"HTTP {resp.status_code} Location: {location}"],
                    recommendation="Change to a 301 (permanent) redirect.",
                ))
            else:
                self._add(Finding("HTTPS Redirect", "PASS", "PASS",
                                   f"HTTP correctly redirects to HTTPS "
                                   f"(HTTP {resp.status_code})."))
        elif parsed.scheme == "http":
            self._add(Finding(
                name="No HTTP → HTTPS Redirect",
                severity="MEDIUM",
                status="VULNERABLE",
                detail="Site is served over HTTP with no redirect to HTTPS.",
                evidence=[f"HTTP {resp.status_code} — no Location to https://"],
                recommendation=(
                    "Enforce HTTPS in IIS Manager → SSL Settings or via URL Rewrite "
                    "rules, and set HSTS (Strict-Transport-Security) header."
                ),
            ))
        else:
            self._add(Finding("HTTPS Redirect", "PASS", "PASS",
                               "Site is already using HTTPS."))

    # ══════════════════════════════════════════════════════════════════════════
    # Run all checks
    # ══════════════════════════════════════════════════════════════════════════

    def run(self):
        console.print(Panel(
            f"[bold cyan]{BANNER}[/bold cyan]\n"
            f"[dim]Target :[/dim] [bold]{self.base_url}[/bold]\n"
            f"[dim]SSL verify:[/dim] {self.verify_ssl}   "
            f"[dim]Timeout:[/dim] {self.timeout}s   "
            f"[dim]shortscan:[/dim] {self.shortscan_path or 'not found'}",
            title=f"[bold white]IIS Scanner v{VERSION}[/bold white]",
            border_style="cyan",
        ))

        self.check_server_banner()
        self.check_security_headers()
        self.check_default_iis_page()
        self.check_aspnet_version_4()
        self.check_verbose_errors()
        self.check_trace_axd()
        self.check_debug_mode()
        self.check_tilde_shortname()
        self.check_internal_ip_disclosure()
        self.check_http_methods()
        self.check_directory_browsing()
        self.check_sensitive_files()
        self.check_httpapi_banner()
        self.check_cookie_security()
        self.check_https_redirect()

        print_summary(self.findings)


# ═══════════════════════════════════════════════════════════════════════════════
# Prerequisite check
# ═══════════════════════════════════════════════════════════════════════════════

def find_shortscan() -> Optional[str]:
    """Return path to shortscan binary, or None if not found."""
    # 1 – PATH
    found = shutil.which("shortscan")
    if found:
        return found
    # 2 – Common Go bin locations
    candidates = [
        os.path.expanduser("~/go/bin/shortscan"),
        os.path.join(os.environ.get("GOPATH", ""), "bin", "shortscan"),
        "/usr/local/go/bin/shortscan",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def check_prerequisites() -> Optional[str]:
    """
    Verify shortscan is installed.  If not, print instructions and return None.
    Returns the path to shortscan if found.
    """
    path = find_shortscan()
    if path:
        console.print(f"[bold green]✔[/bold green] shortscan found at [dim]{path}[/dim]")
        return path

    console.print(Panel(
        "[bold red]shortscan is not installed.[/bold red]\n\n"
        "The tilde shortname check (Check 8) requires shortscan.\n"
        "Install it with:\n\n"
        "  [bold cyan]go install github.com/bitquark/shortscan/cmd/shortscan@latest[/bold cyan]\n\n"
        "Ensure [bold]$GOPATH/bin[/bold] (typically [dim]~/go/bin[/dim]) is in your [bold]$PATH[/bold]:\n\n"
        "  [bold cyan]export PATH=$PATH:$(go env GOPATH)/bin[/bold cyan]\n\n"
        "Check 8 will be skipped for this run.",
        title="[bold yellow]⚠  Missing Dependency[/bold yellow]",
        border_style="yellow",
    ))
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iis_scanner",
        description="IIS Web Vulnerability Scanner — checks for common IIS misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 iis_scanner.py http://target.example.com
  python3 iis_scanner.py https://target.example.com --verify-ssl
  python3 iis_scanner.py http://10.0.0.5 --proxy http://127.0.0.1:8080 --timeout 20
  python3 iis_scanner.py http://target.example.com --no-shortscan
""",
    )
    p.add_argument("url",
                   help="Target URL (e.g. http://target.com or https://target.com)")
    p.add_argument("--verify-ssl", action="store_true", default=False,
                   help="Verify SSL/TLS certificates (default: disabled)")
    p.add_argument("--timeout", type=int, default=10, metavar="SECONDS",
                   help="HTTP request timeout in seconds (default: 10)")
    p.add_argument("--proxy", metavar="URL",
                   help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--user-agent", metavar="STRING",
                   help="Custom User-Agent string")
    p.add_argument("--no-shortscan", action="store_true", default=False,
                   help="Skip the tilde shortname check (Check 8)")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Prerequisite check
    shortscan_path = None
    if not args.no_shortscan:
        shortscan_path = check_prerequisites()
    else:
        console.print("[dim]shortscan check skipped (--no-shortscan)[/dim]")

    scanner = IISScanner(
        url=args.url,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
        proxy=args.proxy,
        user_agent=args.user_agent,
        shortscan_path=shortscan_path,
    )
    scanner.run()


if __name__ == "__main__":
    main()
