import math
import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
from app.models.schemas import EvidenceItem, Severity
from app.services.company_verifier import SUSPICIOUS_TLDS

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rb.gy", "shorturl.at", "ow.ly", "buff.ly"
}

PHISHING_KEYWORDS = [
    "verify", "login", "portal", "careers-portal", "job-apply", "offer-letter",
    "secure-login", "hr-desk", "interview-pass", "gatepass", "candidate-portal"
]

IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

class URLAnalyzer:
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon entropy to detect algorithmically generated domains or token stuffing."""
        if not text:
            return 0.0
        entropy = 0.0
        for char in set(text):
            p = text.count(char) / len(text)
            entropy -= p * math.log2(p)
        return entropy

    def analyze_url(self, url: str, company_hint: Optional[str] = None) -> Tuple[float, List[EvidenceItem], List[str], List[str]]:
        """
        Analyzes a URL for malicious / scam patterns.
        Returns:
            - url_risk (0 to 100)
            - evidence_list
            - major_warnings
            - positive_signals
        """
        if not url or not url.strip():
            return 0.0, [], [], []

        clean_url = url.strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            clean_url = "https://" + clean_url

        try:
            parsed = urlparse(clean_url)
        except Exception:
            return 75.0, [EvidenceItem(
                category="URL Structure",
                severity=Severity.HIGH,
                title="Malformed URL",
                explanation="The provided URL is structurally corrupted or unparseable."
            )], ["Malformed URL"], []

        hostname = (parsed.netloc or "").lower().split(":")[0]
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()

        risk_score = 10.0 # baseline neutral
        evidence: List[EvidenceItem] = []
        major_warnings: List[str] = []
        positive_signals: List[str] = []

        # 1. Check Protocol (HTTP vs HTTPS)
        if parsed.scheme == "http":
            risk_score += 25.0
            evidence.append(EvidenceItem(
                category="Transport Security",
                severity=Severity.HIGH,
                title="Unencrypted HTTP Protocol",
                explanation="Legitimate enterprise career platforms mandate TLS/HTTPS encryption. Plain HTTP exposes credentials and indicates lack of security compliance.",
                matched_phrase=clean_url
            ))
            major_warnings.append("Security Alert: Application link is insecure HTTP (no SSL/TLS)")
        elif parsed.scheme == "https":
            positive_signals.append("Encrypted HTTPS connection")

        # 2. Check for Raw IP Address Hostname
        if IP_PATTERN.match(hostname):
            risk_score += 65.0
            evidence.append(EvidenceItem(
                category="Network Anomaly",
                severity=Severity.CRITICAL,
                title="Direct IP Address Host",
                explanation=f"URL points directly to an IP address ({hostname}) rather than a registered enterprise domain name.",
                matched_phrase=hostname
            ))
            major_warnings.append(f"Host Threat: URL points to raw IP ({hostname}) without legitimate domain")

        # 3. Check for URL Shorteners
        if hostname in SHORTENER_DOMAINS:
            risk_score += 35.0
            evidence.append(EvidenceItem(
                category="Obfuscation",
                severity=Severity.HIGH,
                title="Shortened / Obfuscated Link",
                explanation=f"URL uses link shortener ({hostname}) to disguise the actual target destination. Common in phishing scams.",
                matched_phrase=hostname
            ))
            major_warnings.append(f"Obfuscation: URL hides true destination via shortener ({hostname})")

        # 4. Check for Suspicious Top-Level Domains (TLDs)
        matched_tld = next((tld for tld in SUSPICIOUS_TLDS if hostname.endswith(tld)), None)
        if matched_tld:
            risk_score += 40.0
            evidence.append(EvidenceItem(
                category="Domain Reputation",
                severity=Severity.HIGH,
                title=f"High-Risk TLD ({matched_tld})",
                explanation=f"Domain ends in '{matched_tld}', which has very high abuse rates and is rarely used by legitimate corporate employers.",
                matched_phrase=matched_tld
            ))
            major_warnings.append(f"Suspicious Domain: High-risk TLD '{matched_tld}' detected")

        # 5. Check Subdomain Stacking / Deceptive Brand Infix
        subdomains = hostname.split(".")
        if len(subdomains) > 3:
            risk_score += 20.0
            evidence.append(EvidenceItem(
                category="Domain Structure",
                severity=Severity.MEDIUM,
                title="Excessive Subdomain Stacking",
                explanation=f"Host '{hostname}' has {len(subdomains)} domain segments, commonly used to spoof brand names in deep subdomains.",
                matched_phrase=hostname
            ))

        # Check if brand appears in subdomain or path but actual root domain belongs to third party
        if company_hint:
            comp_clean = re.sub(r'[^a-zA-Z0-9]', '', company_hint.lower())
            if len(comp_clean) >= 4 and comp_clean in hostname:
                root_domain = ".".join(subdomains[-2:])
                if comp_clean not in root_domain:
                    risk_score += 60.0
                    evidence.append(EvidenceItem(
                        category="Phishing Impersonation",
                        severity=Severity.CRITICAL,
                        title="Brand Deception in Subdomain",
                        explanation=f"URL contains '{comp_clean}' as a subdomain, but the actual owning domain is '{root_domain}'. High probability of phishing spoofing.",
                        matched_phrase=hostname
                    ))
                    major_warnings.append(f"Phishing Spoof: Brand name is placed in subdomain while domain is '{root_domain}'")

        # 6. Check Phishing Keywords in Path or Query
        found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in path or kw in query]
        if found_keywords:
            risk_score += 15.0
            evidence.append(EvidenceItem(
                category="Linguistic URL Match",
                severity=Severity.MEDIUM,
                title="Credential Harvest Keywords in URL",
                explanation=f"URL path contains target terms: {', '.join(found_keywords)}.",
                matched_phrase=", ".join(found_keywords)
            ))

        # 7. Shannon Entropy on Domain
        domain_entropy = self.calculate_entropy(hostname)
        if domain_entropy > 4.2:
            risk_score += 25.0
            evidence.append(EvidenceItem(
                category="Heuristic Analysis",
                severity=Severity.HIGH,
                title="High Domain Entropy (Randomness)",
                explanation=f"Hostname entropy is {domain_entropy:.2f}, indicating possible algorithmically generated domain (DGA).",
                matched_phrase=hostname
            ))

        # Check for known trustworthy platforms (LinkedIn, Indeed, Internshala, Naukri, Wellfound, Unstop)
        TRUSTED_PORTALS = ["linkedin.com", "internshala.com", "indeed.com", "naukri.com", "unstop.com", "wellfound.com", "greenhouse.io", "lever.co", "workday.com"]
        if any(hostname.endswith(t) for t in TRUSTED_PORTALS):
            risk_score = max(5.0, risk_score - 35.0)
            positive_signals.append(f"Reputable job board / ATS host detected ({hostname})")

        return min(100.0, max(0.0, risk_score)), evidence, major_warnings, positive_signals
