import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from app.models.schemas import (
    AnalysisResult, RiskBreakdown, RiskLevel, Verdict,
    EvidenceItem, Severity, ExtractedEntities
)

class RiskAssessmentEngine:
    def __init__(self):
        # Base signal weights (normalized to 1.0)
        self.weights = {
            "payment": 0.30,
            "job_content": 0.20,
            "company": 0.15,
            "recruiter": 0.15,
            "url": 0.10,
            "document": 0.10
        }

    def calculate_assessment(
        self,
        job_content_risk: float = 0.0,
        company_risk: float = 0.0,
        recruiter_risk: float = 0.0,
        url_risk: float = 0.0,
        payment_risk: float = 0.0,
        document_risk: float = 0.0,
        evidence_list: Optional[List[EvidenceItem]] = None,
        major_warnings: Optional[List[str]] = None,
        minor_cautions: Optional[List[str]] = None,
        positive_signals: Optional[List[str]] = None,
        extracted_entities: Optional[ExtractedEntities] = None,
        student_safety_mode: bool = True
    ) -> AnalysisResult:
        """
        Synthesizes multimodal evidence signals into a calibrated 0-100 risk score and explainable verdict.
        """
        evidence_list = evidence_list or []
        major_warnings = list(dict.fromkeys(major_warnings or []))
        minor_cautions = list(dict.fromkeys(minor_cautions or []))
        positive_signals = list(dict.fromkeys(positive_signals or []))
        extracted_entities = extracted_entities or ExtractedEntities()

        # 1. Base Weighted Score
        base_score = (
            payment_risk * self.weights["payment"] +
            job_content_risk * self.weights["job_content"] +
            company_risk * self.weights["company"] +
            recruiter_risk * self.weights["recruiter"] +
            url_risk * self.weights["url"] +
            document_risk * self.weights["document"]
        )

        # 2. Critical Penalty Escalations (Nonlinear risk amplifiers)
        # Rule A: If upfront payment is requested, risk must not be lower than 75
        if payment_risk >= 75:
            base_score = max(base_score, 82.0 + (payment_risk - 75) * 0.6)

        # Rule B: If recruiter uses @gmail while claiming to be Fortune 500 company
        if recruiter_risk >= 80:
            base_score = max(base_score, 78.0)

        # Rule C: If Student Safety Mode is enabled, elevate risk for high-risk fresher traps
        student_alerts = []
        if student_safety_mode:
            if payment_risk >= 30:
                base_score = min(100.0, base_score + 10.0)
                student_alerts.append("Fresher Protection Alert: Legitimate internships NEVER charge candidates for application, training, or equipment.")
            if any("marksheet" in w.lower() or "cheque" in w.lower() or "certificate" in w.lower() for w in major_warnings):
                base_score = min(100.0, base_score + 15.0)
                student_alerts.append("Document Safety Warning: Surrendering original certificates or blank cheques is illegal under labor regulations.")
            if any("daily" in w.lower() or "like" in w.lower() for w in major_warnings):
                student_alerts.append("Task Scam Warning: Part-time 'YouTube like' or 'review rating' tasks are front operations for cyber fraud syndicates.")

        # Deductions for strong positive signals
        if len(positive_signals) >= 2 and base_score < 60:
            base_score = max(5.0, base_score - (len(positive_signals) * 6.0))

        final_score = round(min(100.0, max(0.0, base_score)), 1)

        # 3. Categorize Risk Level & Actionable Verdict
        if final_score < 30.0:
            risk_level = RiskLevel.LOW
            verdict = Verdict.APPLY
            badge_color = "#10b981" # Emerald Green
            summary = "Low Risk Profile. The evaluated opportunity exhibits characteristics consistent with genuine corporate recruitment. No high-risk fee demands or impersonation patterns were identified."
        elif final_score < 70.0:
            risk_level = RiskLevel.MEDIUM
            verdict = Verdict.VERIFY
            badge_color = "#f59e0b" # Amber Yellow
            summary = "Moderate Risk Profile. Several suspicious or non-standard indicators were flagged. Proceed with caution and verify recruiter identity through official corporate channels before sharing private data."
        elif final_score < 88.0:
            risk_level = RiskLevel.HIGH
            verdict = Verdict.AVOID
            badge_color = "#f97316" # Orange-Red
            summary = "High Risk Detected. Strong indicators of recruitment fraud or phishing. Do NOT pay any advance fees or disclose banking details."
        else:
            risk_level = RiskLevel.CRITICAL
            verdict = Verdict.AVOID
            badge_color = "#ef4444" # Crimson Red
            summary = "CRITICAL THREAT: Severe recruitment scam or cyber fraud operation detected. Immediately cease communication and report to cyber authorities."

        # 4. Generate Practical Next-Step Recommendations
        recommendations = []
        if verdict == Verdict.APPLY:
            recommendations.append("Apply through the verified corporate career portal or reputable job board.")
            recommendations.append("Keep standard caution: never share passwords, OTPs, or bank account PINs.")
            recommendations.append("Ensure official written communication originates from the company's verified email domain.")
        elif verdict == Verdict.VERIFY:
            recommendations.append("Cross-check the job ID on the official company careers page (e.g., company.com/careers).")
            recommendations.append("Look up the recruiter on LinkedIn to verify their current employment and tenure.")
            recommendations.append("Never pay any 'refundable deposit', 'uniform fee', or 'laptop dispatch fee'.")
            recommendations.append("Request an interview via an enterprise meeting link (Google Meet / MS Teams / Zoom) rather than text chat.")
        else: # AVOID
            recommendations.append("DO NOT transfer any money via UPI, NetBanking, Credit Card, or Crypto.")
            recommendations.append("DO NOT send scans of your Aadhaar card, PAN card, blank signed cheques, or original degree marksheets.")
            recommendations.append("Block the scammer on WhatsApp, Telegram, or Email.")
            recommendations.append("File an incident report on the National Cyber Crime Reporting Portal at https://cybercrime.gov.in or dial 1930.")

        breakdown = RiskBreakdown(
            job_content_risk=round(job_content_risk, 1),
            company_verification_risk=round(company_risk, 1),
            recruiter_risk=round(recruiter_risk, 1),
            url_risk=round(url_risk, 1),
            payment_risk=round(payment_risk, 1),
            document_risk=round(document_risk, 1)
        )

        return AnalysisResult(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            risk_score=final_score,
            risk_level=risk_level,
            verdict=verdict,
            verdict_badge_color=badge_color,
            executive_summary=summary,
            breakdown=breakdown,
            major_warnings=major_warnings,
            minor_cautions=minor_cautions,
            positive_signals=positive_signals,
            recommendations=recommendations,
            student_safety_alerts=student_alerts,
            evidence_list=evidence_list,
            extracted_entities=extracted_entities,
            student_safety_mode_active=student_safety_mode
        )
