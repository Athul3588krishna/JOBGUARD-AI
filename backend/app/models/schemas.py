from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Verdict(str, Enum):
    APPLY = "APPLY"
    VERIFY = "VERIFY"
    AVOID = "AVOID"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EvidenceItem(BaseModel):
    category: str
    severity: Severity
    title: str
    explanation: str
    matched_phrase: Optional[str] = None

class RiskBreakdown(BaseModel):
    job_content_risk: float = Field(0.0, ge=0.0, le=100.0, description="Semantic and linguistic scam patterns in posting text")
    company_verification_risk: float = Field(0.0, ge=0.0, le=100.0, description="Company legitimacy, domain mismatch & registrar trust")
    recruiter_risk: float = Field(0.0, ge=0.0, le=100.0, description="Recruiter email validity, disposable accounts & communication channels")
    url_risk: float = Field(0.0, ge=0.0, le=100.0, description="Malicious domain features, phishing links, high-risk TLDs")
    payment_risk: float = Field(0.0, ge=0.0, le=100.0, description="Upfront fees, registration deposits, training charges, crypto/UPI requests")
    document_risk: float = Field(0.0, ge=0.0, le=100.0, description="PDF anomalies, metadata tampering, font inconsistencies, fake stamps")

class ExtractedEntities(BaseModel):
    company_name: Optional[str] = None
    role_title: Optional[str] = None
    salary_offered: Optional[str] = None
    contact_emails: List[str] = []
    contact_phones: List[str] = []
    telegram_handles: List[str] = []
    upi_ids: List[str] = []
    urls: List[str] = []
    payment_amounts_detected: List[str] = []

class AnalysisResult(BaseModel):
    id: str
    timestamp: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: RiskLevel
    verdict: Verdict
    verdict_badge_color: str
    executive_summary: str
    breakdown: RiskBreakdown
    major_warnings: List[str]
    minor_cautions: List[str]
    positive_signals: List[str]
    recommendations: List[str]
    student_safety_alerts: List[str] = []
    evidence_list: List[EvidenceItem] = []
    extracted_entities: ExtractedEntities = ExtractedEntities()
    student_safety_mode_active: bool = False

class JobAnalysisRequest(BaseModel):
    job_title: Optional[str] = None
    company_name: Optional[str] = None
    job_description: str
    job_url: Optional[str] = None
    recruiter_name: Optional[str] = None
    recruiter_email: Optional[str] = None
    recruiter_phone: Optional[str] = None
    salary_mentioned: Optional[str] = None
    location: Optional[str] = None
    student_safety_mode: bool = True

class URLAnalysisRequest(BaseModel):
    url: str
    company_context: Optional[str] = None

class ConsistencyAnalysisRequest(BaseModel):
    job_title: Optional[str] = ""
    job_company: Optional[str] = ""
    job_description: str
    job_salary: Optional[str] = ""
    job_location: Optional[str] = ""
    
    offer_role: Optional[str] = ""
    offer_company: Optional[str] = ""
    offer_text: str
    offer_salary: Optional[str] = ""
    offer_location: Optional[str] = ""
    offer_deposit_requested: Optional[str] = ""

class ScreenshotAnalysisRequest(BaseModel):
    image_base64: Optional[str] = None
    extracted_text_override: Optional[str] = None
    chat_platform: Optional[str] = "generic" # whatsapp, telegram, email, sms
    student_safety_mode: bool = True

class CommunityReportCreate(BaseModel):
    company_name: str
    job_title: str
    scam_type: str # "Upfront Fee", "Telegram Task Scam", "Fake MNC Offer", "Identity Theft", "Malicious URL"
    scammer_email: Optional[str] = None
    scammer_phone: Optional[str] = None
    scammer_telegram: Optional[str] = None
    scam_url: Optional[str] = None
    description: str
    money_demanded: Optional[float] = 0.0
    evidence_text: Optional[str] = None

class CommunityReportItem(CommunityReportCreate):
    id: str
    reported_at: str
    upvotes: int = 0
    verification_status: str = "COMMUNITY_VERIFIED"
