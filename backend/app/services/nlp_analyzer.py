import re
from typing import Dict, List, Any, Tuple
from app.models.schemas import ExtractedEntities, EvidenceItem, Severity

# Known Fortune 500 & Top Employers for domain impersonation checks
KNOWN_ENTERPRISES = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "tcs": "tcs.com",
    "tata consultancy services": "tcs.com",
    "infosys": "infosys.com",
    "wipro": "wipro.com",
    "accenture": "accenture.com",
    "cognizant": "cognizant.com",
    "deloitte": "deloitte.com",
    "ibm": "ibm.com",
    "meta": "meta.com",
    "flipkart": "flipkart.com",
    "zomato": "zomato.com",
    "swiggy": "swiggy.in",
    "reliance": "ril.com",
    "jio": "jio.com",
    "hcl": "hcltech.com",
    "tech mahindra": "techmahindra.com"
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "rediffmail.com",
    "protonmail.com", "proton.me", "mail.com", "zoho.com", "yopmail.com",
    "tempmail.com", "gmx.com", "icloud.com"
}

# Regex patterns
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_REGEX = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\+91[-.\s]?[6-9]\d{9}|[6-9]\d{9}')
TELEGRAM_REGEX = re.compile(r'(?:@([a-zA-Z0-9_]{4,32})|t\.me/([a-zA-Z0-9_]{4,32}))', re.IGNORECASE)
UPI_REGEX = re.compile(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}')
URL_REGEX = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
MONEY_REGEX = re.compile(r'(?:₹|INR|Rs\.?|\$)\s*([\d,]+(?:\.\d{2})?)', re.IGNORECASE)

class NLPAnalyzer:
    def __init__(self):
        # Scam signal taxonomy with weighted penalties
        self.payment_keywords = [
            (r'\b(registration\s+fee|registration\s+charge|entry\s+fee)\b', "Upfront Registration Fee", 35, Severity.CRITICAL),
            (r'\b(training\s+fee|training\s+cost|certification\s+charge)\b', "Mandatory Training Payment", 30, Severity.HIGH),
            (r'\b(security\s+deposit|refundable\s+deposit|caution\s+deposit)\b', "Security Deposit Demanded", 35, Severity.CRITICAL),
            (r'\b(laptop\s+fee|courier\s+charge|delivery\s+fee|dispatch\s+cost)\b', "Hardware / Laptop Courier Fee", 30, Severity.HIGH),
            (r'\b(interview\s+slot\s+booking|slot\s+fee|gate\s+pass\s+fee)\b', "Paid Interview Slot", 35, Severity.CRITICAL),
            (r'\b(processing\s+fee|documentation\s+charge|verification\s+fee)\b', "Offer Processing Fee", 25, Severity.HIGH),
            (r'\b(uniform\s+fee|id\s+card\s+charge|badge\s+fee)\b', "Uniform / Badge Charge", 25, Severity.HIGH),
            (r'\b(crypto|usdt|bitcoin|binance|telegram\s+wallet)\b', "Cryptocurrency Payment Mechanism", 35, Severity.CRITICAL),
            (r'\b(upi\s+transfer|gpay|phonepe|paytm\s+to\s+confirm)\b', "Direct UPI Payment Request", 30, Severity.HIGH)
        ]

        self.task_scam_keywords = [
            (r'\b(like\s+(?:and\s+)?subscribe|youtube\s+like|video\s+rating)\b', "YouTube / Social Media Task Scheme", 35, Severity.CRITICAL),
            (r'\b(hotel\s+review|google\s+map\s+review|tripadvisor\s+review)\b', "Fake Review / Rating Task Scheme", 30, Severity.HIGH),
            (r'\b(earn\s+(?:rs\.?|inr|₹)?\s*\d{3,5}\s*(?:daily|per\s+day))\b', "Unrealistic Daily Wage Claim", 25, Severity.HIGH),
            (r'\b(part\s+time\s+task|prepaid\s+task|vip\s+mission)\b', "Prepaid Task-Based Scam Pattern", 35, Severity.CRITICAL),
            (r'\b(recharge\s+your\s+account|deposit\s+funds\s+to\s+unlock)\b', "Recharge-to-Unlock Task Scam", 40, Severity.CRITICAL)
        ]

        self.urgency_keywords = [
            (r'\b(immediate\s+joining|urgent\s+selection|direct\s+selection\s+without\s+interview)\b', "No-Interview Direct Selection", 25, Severity.HIGH),
            (r'\b(only\s+\d+\s+slots?\s+left|limited\s+seats?|hurry\s+up)\b', "High-Pressure Artificial Urgency", 15, Severity.MEDIUM),
            (r'\b(valid\s+only\s+for\s+\d+\s+hours?|expires\s+in\s+\d+\s+minutes?)\b', "Arbitrary Tight Deadline", 15, Severity.MEDIUM),
            (r'\b(100%\s+guaranteed\s+job|100%\s+selection)\b', "Guaranteed Employment Claim", 20, Severity.MEDIUM)
        ]

        self.sensitive_data_keywords = [
            (r'\b(blank\s+cheque|cancelled\s+cheque\s+with\s+sign)\b', "Request for Signed Cheques", 40, Severity.CRITICAL),
            (r'\b(aadhaar\s+otp|bank\s+otp|card\s+cvv|atm\s+pin)\b', "Direct Banking Credential Harvesting", 50, Severity.CRITICAL),
            (r'\b(submit\s+original\s+certificates|surrender\s+original\s+marksheet)\b', "Surrender of Original Marksheets/Certificates", 35, Severity.CRITICAL),
            (r'\b(pay\s+bond\s+amount\s+if\s+you\s+leave)\b', "Illegal Penalty Bond Agreement", 25, Severity.HIGH)
        ]

        self.positive_keywords = [
            (r'\b(we\s+never\s+ask\s+for\s+money|no\s+application\s+fee|free\s+recruitment)\b', "Explicit No-Fee Equal Opportunity Disclaimer"),
            (r'\b(official\s+career\s+portal|careers\.[a-z0-9-]+\.(?:com|org))\b', "Official Enterprise Career Portal Mention"),
            (r'\b(comprehensive\s+health\s+insurance|provident\s+fund|pf\s+contribution|gratuity)\b', "Standard Corporate Benefits Package"),
            (r'\b(technical\s+interview\s+rounds?|coding\s+assessment|system\s+design)\b', "Rigorous Multi-Stage Interview Process")
        ]

    def extract_entities(self, text: str) -> ExtractedEntities:
        """Extracts structured entities such as emails, phone numbers, UPIs, URLs, and currencies from raw text."""
        emails = list(set(EMAIL_REGEX.findall(text)))
        
        # Phone numbers
        raw_phones = PHONE_REGEX.findall(text)
        phones = list(set([p.strip() for p in raw_phones if len(re.sub(r'\D', '', p)) >= 10]))
        
        # Telegram handles
        tg_matches = TELEGRAM_REGEX.findall(text)
        telegrams = []
        for m in tg_matches:
            handle = m[0] or m[1]
            if handle and handle.lower() not in ["channel", "group", "bot"]:
                telegrams.append(f"@{handle}")
        telegrams = list(set(telegrams))

        # UPI handles
        upis = [u for u in UPI_REGEX.findall(text) if any(v in u.lower() for v in ["@upi", "@paytm", "@oksbi", "@okhdfc", "@okaxis", "@icici", "@ybl", "@axl"])]
        
        # URLs
        urls = list(set(URL_REGEX.findall(text)))

        # Money
        money = list(set(MONEY_REGEX.findall(text)))

        return ExtractedEntities(
            contact_emails=emails,
            contact_phones=phones,
            telegram_handles=telegrams,
            upi_ids=upis,
            urls=urls,
            payment_amounts_detected=money
        )

    def analyze_text(self, text: str, company_hint: str = None, student_safety_mode: bool = True) -> Tuple[float, List[EvidenceItem], List[str], List[str], List[str]]:
        """
        Analyzes the linguistic and semantic indicators of the job posting or communication text.
        Returns:
            - job_content_risk (0 to 100)
            - evidence_list (structured evidence items)
            - major_warnings
            - minor_cautions
            - positive_signals
        """
        raw_score = 0.0
        evidence_list: List[EvidenceItem] = []
        major_warnings: List[str] = []
        minor_cautions: List[str] = []
        positive_signals: List[str] = []

        lower_text = text.lower()

        # 1. Scan Payment Keywords
        for pattern, label, weight, severity in self.payment_keywords:
            match = re.search(pattern, lower_text)
            if match:
                matched_str = match.group(0)
                # Boost if student safety mode is active
                actual_weight = weight * 1.35 if student_safety_mode else weight
                raw_score += actual_weight
                evidence_list.append(EvidenceItem(
                    category="Payment & Deposit Risk",
                    severity=severity,
                    title=label,
                    explanation=f"Text explicitly mentions '{matched_str}'. Legitimate employers never ask applicants to pay any fees.",
                    matched_phrase=matched_str
                ))
                major_warnings.append(f"Financial Demand: {label} detected ('{matched_str}')")

        # 2. Scan Task / Telegram Scams
        for pattern, label, weight, severity in self.task_scam_keywords:
            match = re.search(pattern, lower_text)
            if match:
                matched_str = match.group(0)
                raw_score += weight
                evidence_list.append(EvidenceItem(
                    category="Task / Commission Scam",
                    severity=severity,
                    title=label,
                    explanation=f"Pattern '{matched_str}' is characteristic of high-volume online task/commission frauds.",
                    matched_phrase=matched_str
                ))
                major_warnings.append(f"Scam Blueprint: {label} ('{matched_str}')")

        # 3. Urgency & Direct Selection
        for pattern, label, weight, severity in self.urgency_keywords:
            match = re.search(pattern, lower_text)
            if match:
                matched_str = match.group(0)
                raw_score += weight
                evidence_list.append(EvidenceItem(
                    category="Psychological Manipulation",
                    severity=severity,
                    title=label,
                    explanation=f"Phrases like '{matched_str}' use artificial urgency to push victims into bypassing scrutiny.",
                    matched_phrase=matched_str
                ))
                minor_cautions.append(f"Pressure Tactic: {label}")

        # 4. Sensitive Data Harvesting
        for pattern, label, weight, severity in self.sensitive_data_keywords:
            match = re.search(pattern, lower_text)
            if match:
                matched_str = match.group(0)
                raw_score += weight * (1.2 if student_safety_mode else 1.0)
                evidence_list.append(EvidenceItem(
                    category="Identity & Financial Credential Theft",
                    severity=severity,
                    title=label,
                    explanation=f"Hazardous request detected: '{matched_str}'. Risk of bank drain or document extortion.",
                    matched_phrase=matched_str
                ))
                major_warnings.append(f"Severe Danger: {label} requested in recruitment phase")

        # 5. Positive Signals (Deductions)
        for pattern, label in self.positive_keywords:
            match = re.search(pattern, lower_text)
            if match:
                positive_signals.append(label)
                raw_score -= 12.0

        # Cap score between 0 and 100
        content_risk = max(0.0, min(100.0, raw_score))
        return content_risk, evidence_list, major_warnings, minor_cautions, positive_signals
