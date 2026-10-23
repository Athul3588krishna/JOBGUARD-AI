import io
import re
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import pypdf
from app.models.schemas import EvidenceItem, Severity, ExtractedEntities
from app.services.nlp_analyzer import NLPAnalyzer, KNOWN_ENTERPRISES, FREE_EMAIL_DOMAINS

SUSPICIOUS_PRODUCERS = [
    "canva", "ilovepdf", "smallpdf", "pdf2go", "photoshop", "gimp",
    "wondershare", "sejda", "pdfescape", "paint.net"
]

class PDFForensics:
    def __init__(self):
        self.nlp = NLPAnalyzer()

    def analyze_pdf_bytes(self, file_bytes: bytes, filename: str = "offer_letter.pdf") -> Dict[str, Any]:
        """
        Performs in-depth forensic analysis on an uploaded PDF offer letter.
        """
        evidence: List[EvidenceItem] = []
        major_warnings: List[str] = []
        minor_cautions: List[str] = []
        positive_signals: List[str] = []
        extracted_text = ""
        metadata: Dict[str, Any] = {}
        document_risk = 15.0 # baseline
        is_encrypted = False

        try:
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            is_encrypted = reader.is_encrypted
            page_count = len(reader.pages)

            # 1. Extract text from pages
            page_texts = []
            for i, page in enumerate(reader.pages):
                txt = page.extract_text() or ""
                page_texts.append(txt)
            extracted_text = "\n".join(page_texts)

            # 2. Extract Document Metadata
            raw_meta = reader.metadata or {}
            for k, v in raw_meta.items():
                clean_k = k.replace("/", "")
                metadata[clean_k] = str(v)

            creator = str(metadata.get("Creator", "")).lower()
            producer = str(metadata.get("Producer", "")).lower()
            author = str(metadata.get("Author", "")).lower()
            creation_date_str = str(metadata.get("CreationDate", ""))
            mod_date_str = str(metadata.get("ModDate", ""))

            # Forensics on PDF Software / Producer
            for tool in SUSPICIOUS_PRODUCERS:
                if tool in creator or tool in producer or tool in author:
                    document_risk += 45.0
                    evidence.append(EvidenceItem(
                        category="Forensic Metadata",
                        severity=Severity.HIGH,
                        title=f"Unprofessional Document Authoring Tool ({tool.title()})",
                        explanation=f"Offer letter was generated using '{tool}'. Legitimate enterprises utilize official HR document generators, Adobe Acrobat Enterprise, or DocuSign, rather than ad-hoc consumer design tools.",
                        matched_phrase=f"Producer: {producer or creator}"
                    ))
                    major_warnings.append(f"Forensic Anomaly: Document created via '{tool.title()}' graphic editing suite")
                    break

            # Digital Signature Check
            # Check if certified digital signature is present in PDF catalog
            has_digital_signature = False
            try:
                if "/AcroForm" in reader.trailer.get("/Root", {}) and "/SigFlags" in reader.trailer["/Root"]["/AcroForm"]:
                    has_digital_signature = True
            except Exception:
                pass

            if has_digital_signature:
                document_risk = max(0.0, document_risk - 20.0)
                positive_signals.append("Cryptographic Digital Signature block detected")

        except Exception as e:
            # Fallback for non-standard PDF or damaged header
            document_risk += 40.0
            evidence.append(EvidenceItem(
                category="File Integrity",
                severity=Severity.HIGH,
                title="PDF Parsing Exception",
                explanation=f"Document could not be cleanly parsed: {str(e)[:100]}. File might be obfuscated, corrupted, or non-standard.",
                matched_phrase=str(e)[:50]
            ))

        # 3. Text-based Forensic Inspection
        nlp_risk, text_evidence, text_warnings, text_cautions, text_positive = self.nlp.analyze_text(extracted_text, student_safety_mode=True)
        evidence.extend(text_evidence)
        major_warnings.extend(text_warnings)
        minor_cautions.extend(text_cautions)
        positive_signals.extend(text_positive)

        # Entity Extraction from Document
        entities = self.nlp.extract_entities(extracted_text)

        # 4. Check for Deposit or Payment clauses in the offer letter
        deposit_match = re.search(r'\b(security\s+deposit|refundable\s+amount|laptop\s+fee|training\s+charge|deposit\s+of\s+(?:₹|inr|rs\.?)\s*[\d,]+)\b', extracted_text, re.IGNORECASE)
        payment_risk = 5.0
        if deposit_match:
            payment_risk = 95.0
            document_risk += 40.0
            evidence.append(EvidenceItem(
                category="Fraudulent Clause",
                severity=Severity.CRITICAL,
                title="Monetary Deposit Mandated in Offer Letter",
                explanation=f"Offer letter explicitly stipulates financial collection: '{deposit_match.group(0)}'. No authentic employer charges employees for joining or work equipment.",
                matched_phrase=deposit_match.group(0)
            ))
            major_warnings.append(f"CRITICAL FRAUD CLAUSE: Offer demands monetary payment ('{deposit_match.group(0)}')")

        # 5. Check if contact email inside offer letter is free webmail
        for email in entities.contact_emails:
            domain = email.split("@")[-1].lower()
            if domain in FREE_EMAIL_DOMAINS:
                document_risk += 35.0
                evidence.append(EvidenceItem(
                    category="Formal Letterhead Integrity",
                    severity=Severity.HIGH,
                    title="Official Offer Letter Uses Free Webmail",
                    explanation=f"Official corporate letterhead lists free contact email '{email}'. Genuine enterprise offers use corporate domain mailboxes.",
                    matched_phrase=email
                ))
                major_warnings.append(f"Letterhead Discrepancy: Official offer lists public email '{email}'")

        # Field Extraction heuristics
        parsed_fields = self._extract_key_fields(extracted_text)

        return {
            "document_risk": min(100.0, max(0.0, document_risk)),
            "payment_risk": min(100.0, max(0.0, payment_risk)),
            "evidence": evidence,
            "major_warnings": major_warnings,
            "minor_cautions": minor_cautions,
            "positive_signals": positive_signals,
            "metadata": metadata,
            "extracted_text": extracted_text,
            "extracted_fields": parsed_fields,
            "entities": entities
        }

    def _extract_key_fields(self, text: str) -> Dict[str, Optional[str]]:
        """Extracts candidate name, company, role, salary, joining date from text."""
        fields: Dict[str, Optional[str]] = {
            "candidate_name": None,
            "company_name": None,
            "designation": None,
            "ctc_salary": None,
            "joining_date": None,
            "stipend_deposit": None
        }

        # Role pattern
        role_match = re.search(r'(?:position\s+of|role\s+of|designated\s+as|appointment\s+for|designation:?)\s*([A-Za-z\s]{3,40})', text, re.IGNORECASE)
        if role_match:
            fields["designation"] = role_match.group(1).strip().split("\n")[0]

        # Salary / CTC pattern
        ctc_match = re.search(r'(?:ctc|salary|stipend|compensation|remuneration)\s*(?:of|is|:)?\s*(?:(?:₹|inr|rs\.?|\$)\s*[\d,]+(?:\s*(?:lpa|per\s+month|p\.a\.|per\s+annum))?)', text, re.IGNORECASE)
        if ctc_match:
            fields["ctc_salary"] = ctc_match.group(0).strip()

        # Date pattern
        date_match = re.search(r'(?:joining\s+date|date\s+of\s+joining|commencing\s+on)\s*(?:is|:)?\s*([0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{2,4}|[A-Za-z]+\s+[0-9]{1,2},?\s+[0-9]{4})', text, re.IGNORECASE)
        if date_match:
            fields["joining_date"] = date_match.group(1).strip()

        # Deposit pattern
        deposit_match = re.search(r'(?:deposit|registration|laptop\s+charges?)\s*(?:of|is|:)?\s*(?:(?:₹|inr|rs\.?|\$)\s*[\d,]+)', text, re.IGNORECASE)
        if deposit_match:
            fields["stipend_deposit"] = deposit_match.group(0).strip()

        return fields
