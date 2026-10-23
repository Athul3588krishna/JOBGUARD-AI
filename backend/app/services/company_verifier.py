import re
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
from app.models.schemas import EvidenceItem, Severity
from app.services.nlp_analyzer import KNOWN_ENTERPRISES, FREE_EMAIL_DOMAINS

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".buzz", ".guru", ".rest",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".live", ".space", ".site", ".online"
}

class CompanyVerifier:
    @staticmethod
    def extract_domain(email_or_url: str) -> Optional[str]:
        """Extracts cleaned base domain from an email or URL string."""
        if not email_or_url:
            return None
        text = email_or_url.strip().lower()
        if "@" in text:
            return text.split("@")[-1].strip()
        if text.startswith("http://") or text.startswith("https://"):
            parsed = urlparse(text)
            return parsed.netloc.split(":")[0]
        # Direct domain text
        parts = text.split("/")
        return parts[0].strip()

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculates edit distance to detect brand lookalikes / typosquatting."""
        if len(s1) < len(s2):
            return CompanyVerifier.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def verify_recruiter_and_company(
        self,
        company_name: Optional[str],
        recruiter_email: Optional[str],
        recruiter_phone: Optional[str],
        recruiter_telegram: Optional[str] = None,
        job_url: Optional[str] = None
    ) -> Tuple[float, float, List[EvidenceItem], List[str], List[str]]:
        """
        Calculates:
        - company_verification_risk (0 to 100)
        - recruiter_risk (0 to 100)
        - evidence_items
        - major_warnings
        - positive_signals
        """
        company_risk = 15.0 # baseline neutral
        recruiter_risk = 20.0 # baseline neutral
        evidence: List[EvidenceItem] = []
        major_warnings: List[str] = []
        positive_signals: List[str] = []

        norm_company = company_name.lower().strip() if company_name else ""

        # 1. Recruiter Email Verification
        if recruiter_email:
            email_clean = recruiter_email.strip().lower()
            domain = self.extract_domain(email_clean)

            if domain:
                is_free_mail = any(domain.endswith(free) for free in FREE_EMAIL_DOMAINS)

                # Check if company is a known enterprise or MNC
                matched_known_domain = None
                if norm_company:
                    for ent_name, ent_domain in KNOWN_ENTERPRISES.items():
                        if ent_name in norm_company:
                            matched_known_domain = ent_domain
                            break

                if matched_known_domain:
                    if is_free_mail:
                        recruiter_risk += 65.0
                        company_risk += 50.0
                        evidence.append(EvidenceItem(
                            category="Recruiter Impersonation",
                            severity=Severity.CRITICAL,
                            title="Corporate Impersonation via Free Email",
                            explanation=f"Recruiter claims to represent '{company_name}' but is using a free public email provider ({domain}) instead of the verified corporate domain '{matched_known_domain}'.",
                            matched_phrase=recruiter_email
                        ))
                        major_warnings.append(f"Impersonation Alert: Recruiter uses free webmail ({domain}) while claiming to be from {company_name}")
                    elif not domain.endswith(matched_known_domain):
                        # Domain mismatch
                        recruiter_risk += 55.0
                        company_risk += 45.0
                        evidence.append(EvidenceItem(
                            category="Domain Inconsistency",
                            severity=Severity.HIGH,
                            title="Recruiter Domain Mismatch",
                            explanation=f"Recruiter domain '@{domain}' does not align with the official company domain '{matched_known_domain}'.",
                            matched_phrase=domain
                        ))
                        major_warnings.append(f"Domain Mismatch: Official enterprise domain is '{matched_known_domain}', but recruiter writes from '@{domain}'")
                    else:
                        # Genuine enterprise domain match!
                        recruiter_risk = max(0.0, recruiter_risk - 25.0)
                        company_risk = max(0.0, company_risk - 25.0)
                        positive_signals.append(f"Verified Corporate Domain Match: @{domain}")
                else:
                    if is_free_mail:
                        recruiter_risk += 35.0
                        evidence.append(EvidenceItem(
                            category="Recruiter Communication",
                            severity=Severity.MEDIUM,
                            title="Recruiter Uses Free Webmail",
                            explanation=f"Communication originated from a generic free webmail provider ({domain}). Authentic HR departments typically operate from custom company domains.",
                            matched_phrase=recruiter_email
                        ))
                    else:
                        positive_signals.append(f"Custom domain email detected: @{domain}")

                # Typosquatting / Lookalike check
                for ent_name, ent_domain in KNOWN_ENTERPRISES.items():
                    ent_core = ent_domain.split(".")[0]
                    domain_core = domain.split(".")[0]
                    dist = self.levenshtein_distance(domain_core, ent_core)
                    if 1 <= dist <= 2 and domain != ent_domain:
                        company_risk += 60.0
                        recruiter_risk += 60.0
                        evidence.append(EvidenceItem(
                            category="Phishing / Typosquatting",
                            severity=Severity.CRITICAL,
                            title="Brand Typosquatting Detected",
                            explanation=f"Domain '{domain}' closely mimics legitimate brand domain '{ent_domain}' (Levenshtein distance {dist}). High probability of phishing clone.",
                            matched_phrase=domain
                        ))
                        major_warnings.append(f"Phishing Risk: Lookalike domain '{domain}' mimics '{ent_domain}'")

        # 2. Check Sole Reliance on Telegram / WhatsApp
        if (recruiter_telegram or (recruiter_phone and not recruiter_email)):
            recruiter_risk += 25.0
            evidence.append(EvidenceItem(
                category="Recruiter Verification",
                severity=Severity.MEDIUM,
                title="Informal Messaging as Primary Channel",
                explanation="Job opportunity relies heavily or exclusively on Telegram or messaging handles rather than verifiable enterprise ATS or corporate email.",
                matched_phrase=recruiter_telegram or recruiter_phone
            ))

        # 3. Check Job URL domain if supplied
        if job_url:
            url_domain = self.extract_domain(job_url)
            if url_domain:
                if any(url_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    company_risk += 30.0
                    evidence.append(EvidenceItem(
                        category="Domain Trust",
                        severity=Severity.HIGH,
                        title="Suspicious or Cheap TLD Used",
                        explanation=f"Domain '{url_domain}' uses a Top-Level Domain frequently associated with throwaway phishing campaigns.",
                        matched_phrase=url_domain
                    ))

        return (
            min(100.0, max(0.0, company_risk)),
            min(100.0, max(0.0, recruiter_risk)),
            evidence,
            major_warnings,
            positive_signals
        )
