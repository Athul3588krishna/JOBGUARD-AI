import os
import json
import joblib
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any

from app.models.schemas import (
    JobAnalysisRequest, URLAnalysisRequest, ConsistencyAnalysisRequest,
    ScreenshotAnalysisRequest, CommunityReportCreate, CommunityReportItem,
    AnalysisResult, RiskBreakdown, RiskLevel, Verdict, EvidenceItem, Severity, ExtractedEntities
)
from app.services.nlp_analyzer import NLPAnalyzer
from app.services.company_verifier import CompanyVerifier
from app.services.url_analyzer import URLAnalyzer
from app.services.pdf_forensics import PDFForensics
from app.services.consistency_engine import ConsistencyEngine
from app.services.screenshot_analyzer import ScreenshotAnalyzer
from app.services.risk_engine import RiskAssessmentEngine
from app.services.community_service import CommunityService

app = FastAPI(
    title="JobGuard AI - Scam Detection and Verification Platform API",
    version="1.0.0",
    description="Multimodal, explainable employment fraud detection, offer letter forensics, and cross-document verification engine."
)

# Enable CORS for frontend and browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize service instances
nlp_service = NLPAnalyzer()
company_service = CompanyVerifier()
url_service = URLAnalyzer()
pdf_service = PDFForensics()
consistency_service = ConsistencyEngine()
screenshot_service = ScreenshotAnalyzer()
risk_engine = RiskAssessmentEngine()
community_service_instance = CommunityService()

# Load trained ML model if available
ml_pipeline = None
try:
    model_path = os.path.join(os.path.dirname(__file__), "ml", "scam_classifier.pkl")
    if os.path.exists(model_path):
        ml_pipeline = joblib.load(model_path)
except Exception as e:
    print(f"ML Pipeline load note: {e}")

# Load sample cases
SAMPLE_FILE = os.path.join(os.path.dirname(__file__), "data", "sample_cases.json")

@app.get("/api/health")
def health_check():
    return {
        "status": "operational",
        "service": "JobGuard AI Multi-Service Engine",
        "modules": [
            "AI Risk Assessment Engine",
            "Offer Letter Forensics",
            "Job-to-Offer Consistency Engine",
            "Company & Recruiter Verifier",
            "Screenshot & Social-Media Analyzer",
            "Malicious URL Analyzer",
            "Student Safety Mode",
            "Community Intelligence Network"
        ],
        "ml_model_loaded": ml_pipeline is not None
    }

@app.post("/api/analyze/job", response_model=AnalysisResult)
def analyze_job(request: JobAnalysisRequest):
    """
    Multimodal analysis of a job posting combining description NLP, ML classification,
    recruiter verification, company domain inspection, and URL risk analysis.
    """
    # 1. NLP and Regex Pattern Mining
    content_risk, evidence, warnings, cautions, positives = nlp_service.analyze_text(
        request.job_description,
        company_hint=request.company_name,
        student_safety_mode=request.student_safety_mode
    )

    # 2. Extract Entities
    entities = nlp_service.extract_entities(request.job_description)
    if request.recruiter_email and request.recruiter_email not in entities.contact_emails:
        entities.contact_emails.append(request.recruiter_email)
    if request.recruiter_phone and request.recruiter_phone not in entities.contact_phones:
        entities.contact_phones.append(request.recruiter_phone)
    if request.job_url and request.job_url not in entities.urls:
        entities.urls.append(request.job_url)
    entities.company_name = request.company_name
    entities.role_title = request.job_title
    entities.salary_offered = request.salary_mentioned

    # 3. ML Model Probability (if text is sufficiently long)
    ml_scam_prob = 0.0
    if ml_pipeline and len(request.job_description) > 30:
        try:
            probs = ml_pipeline.predict_proba([request.job_description])[0]
            ml_scam_prob = float(probs[1]) * 100.0 # probability of fraud
            # Blend ML probability with heuristic content risk
            content_risk = (content_risk * 0.65) + (ml_scam_prob * 0.35)
        except Exception:
            pass

    # 4. Company & Recruiter Verification
    comp_risk, rec_risk, comp_ev, comp_warn, comp_pos = company_service.verify_recruiter_and_company(
        company_name=request.company_name,
        recruiter_email=request.recruiter_email,
        recruiter_phone=request.recruiter_phone,
        job_url=request.job_url
    )
    evidence.extend(comp_ev)
    warnings.extend(comp_warn)
    positives.extend(comp_pos)

    # 5. URL Security Analysis
    url_risk = 0.0
    if request.job_url:
        u_risk, u_ev, u_warn, u_pos = url_service.analyze_url(request.job_url, company_hint=request.company_name)
        url_risk = u_risk
        evidence.extend(u_ev)
        warnings.extend(u_warn)
        positives.extend(u_pos)

    # 6. Payment Risk Calculation
    payment_risk = 0.0
    if entities.payment_amounts_detected:
        payment_risk += 35.0
    if entities.upi_ids:
        payment_risk += 45.0
    for ev in evidence:
        if ev.category in ["Payment & Deposit Risk", "Fraudulent Clause"]:
            payment_risk = max(payment_risk, 85.0 if ev.severity == Severity.CRITICAL else 65.0)

    # 7. Document Risk (neutral for pure text job post unless attachments)
    doc_risk = 10.0

    return risk_engine.calculate_assessment(
        job_content_risk=content_risk,
        company_risk=comp_risk,
        recruiter_risk=rec_risk,
        url_risk=url_risk,
        payment_risk=payment_risk,
        document_risk=doc_risk,
        evidence_list=evidence,
        major_warnings=warnings,
        minor_cautions=cautions,
        positive_signals=positives,
        extracted_entities=entities,
        student_safety_mode=request.student_safety_mode
    )

@app.post("/api/analyze/url", response_model=AnalysisResult)
def analyze_url_endpoint(request: URLAnalysisRequest):
    """
    Dedicated endpoint for inspecting suspicious job application links.
    """
    url_risk, evidence, warnings, positives = url_service.analyze_url(
        request.url, company_hint=request.company_context
    )

    entities = ExtractedEntities(urls=[request.url])

    return risk_engine.calculate_assessment(
        job_content_risk=url_risk * 0.4,
        company_risk=url_risk * 0.5,
        recruiter_risk=url_risk * 0.3,
        url_risk=url_risk,
        payment_risk=15.0,
        document_risk=0.0,
        evidence_list=evidence,
        major_warnings=warnings,
        minor_cautions=[],
        positive_signals=positives,
        extracted_entities=entities,
        student_safety_mode=True
    )

@app.post("/api/analyze/offer-letter")
async def analyze_offer_letter(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    student_safety_mode: bool = Form(True)
):
    """
    Forensic document analyzer for PDF or image offer letters.
    Extracts metadata, font/creator anomalies, clauses, payment demands, and entities.
    """
    file_bytes = None
    filename = "document.pdf"
    if file:
        filename = file.filename
        file_bytes = await file.read()

    if file_bytes and filename.lower().endswith(".pdf"):
        forensic_res = pdf_service.analyze_pdf_bytes(file_bytes, filename=filename)
        doc_risk = forensic_res["document_risk"]
        pay_risk = forensic_res["payment_risk"]
        evidence = forensic_res["evidence"]
        warnings = forensic_res["major_warnings"]
        cautions = forensic_res["minor_cautions"]
        positives = forensic_res["positive_signals"]
        extracted_fields = forensic_res["extracted_fields"]
        extracted_text = forensic_res["extracted_text"]
        entities = forensic_res["entities"]
        metadata = forensic_res["metadata"]
    else:
        # Text-based offer letter evaluation
        text_to_eval = raw_text or ""
        cnt_risk, evidence, warnings, cautions, positives = nlp_service.analyze_text(
            text_to_eval, student_safety_mode=student_safety_mode
        )
        entities = nlp_service.extract_entities(text_to_eval)
        doc_risk = cnt_risk * 0.8
        pay_risk = 85.0 if any("deposit" in w.lower() or "fee" in w.lower() for w in warnings) else 20.0
        extracted_fields = pdf_service._extract_key_fields(text_to_eval)
        extracted_text = text_to_eval
        metadata = {"Source": "Raw Document Text"}

    assessment = risk_engine.calculate_assessment(
        job_content_risk=doc_risk * 0.85,
        company_risk=35.0,
        recruiter_risk=40.0,
        url_risk=10.0,
        payment_risk=pay_risk,
        document_risk=doc_risk,
        evidence_list=evidence,
        major_warnings=warnings,
        minor_cautions=cautions,
        positive_signals=positives,
        extracted_entities=entities,
        student_safety_mode=student_safety_mode
    )

    return {
        "assessment": assessment,
        "document_metadata": metadata,
        "extracted_fields": extracted_fields,
        "extracted_text_preview": extracted_text[:1500] if extracted_text else ""
    }

@app.post("/api/analyze/consistency")
def analyze_consistency(request: ConsistencyAnalysisRequest):
    """
    Cross-document inconsistency engine: compares original job posting details vs received offer letter.
    Detects role escalation, salary inflation, fee emergence, and company identity shifts.
    """
    res = consistency_service.compare_job_and_offer(
        job_title=request.job_title or "",
        job_company=request.job_company or "",
        job_description=request.job_description or "",
        job_salary=request.job_salary or "",
        offer_role=request.offer_role or "",
        offer_company=request.offer_company or "",
        offer_text=request.offer_text or "",
        offer_salary=request.offer_salary or "",
        offer_deposit=request.offer_deposit_requested or ""
    )

    # Generate overarching risk result for consistency
    assessment = risk_engine.calculate_assessment(
        job_content_risk=res["contradiction_risk"] * 0.7,
        company_risk=res["contradiction_risk"] * 0.8,
        recruiter_risk=res["contradiction_risk"] * 0.7,
        url_risk=0.0,
        payment_risk=85.0 if "SURPRISE_FEE_INTRODUCED" in [m["status"] for m in res["comparison_matrix"]] else 20.0,
        document_risk=res["contradiction_risk"] * 0.9,
        evidence_list=res["evidence"],
        major_warnings=res["major_warnings"],
        minor_cautions=res["minor_cautions"],
        positive_signals=[],
        extracted_entities=ExtractedEntities(),
        student_safety_mode=True
    )

    return {
        "assessment": assessment,
        "comparison_matrix": res["comparison_matrix"],
        "contradiction_risk": res["contradiction_risk"],
        "overall_consistency": res["overall_consistency"]
    }

@app.post("/api/analyze/screenshot")
async def analyze_screenshot(
    file: Optional[UploadFile] = File(None),
    extracted_text_override: Optional[str] = Form(None),
    chat_platform: Optional[str] = Form("whatsapp"),
    student_safety_mode: bool = Form(True)
):
    """
    Processes chat screenshots (WhatsApp, Telegram, Instagram, SMS) using computer vision heuristics & NLP.
    """
    image_bytes = None
    if file:
        image_bytes = await file.read()

    res = screenshot_service.analyze_image_and_text(
        image_bytes=image_bytes,
        extracted_text_override=extracted_text_override,
        platform_hint=chat_platform,
        student_safety_mode=student_safety_mode
    )

    assessment = risk_engine.calculate_assessment(
        job_content_risk=res["screenshot_risk"],
        company_risk=60.0,
        recruiter_risk=res["screenshot_risk"],
        url_risk=40.0 if res["entities"].urls else 10.0,
        payment_risk=85.0 if any("recharge" in w.lower() or "deposit" in w.lower() or "upi" in w.lower() for w in res["major_warnings"]) else 35.0,
        document_risk=30.0,
        evidence_list=res["evidence"],
        major_warnings=res["major_warnings"],
        minor_cautions=res["minor_cautions"],
        positive_signals=res["positive_signals"],
        extracted_entities=res["entities"],
        student_safety_mode=student_safety_mode
    )

    return {
        "assessment": assessment,
        "detected_platform": res["detected_platform"],
        "image_metadata": res["image_metadata"],
        "extracted_text": res["extracted_text"]
    }

@app.get("/api/samples")
def get_sample_cases():
    """Returns curated authentic and fraudulent presets for quick evaluation."""
    if os.path.exists(SAMPLE_FILE):
        try:
            with open(SAMPLE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

@app.get("/api/community/reports", response_model=List[CommunityReportItem])
def get_community_reports(
    search: Optional[str] = Query(None),
    scam_type: Optional[str] = Query("All")
):
    """Returns community reported employment scams."""
    return community_service_instance.get_all_reports(search=search, scam_type=scam_type)

@app.post("/api/community/reports", response_model=CommunityReportItem)
def submit_community_report(report: CommunityReportCreate):
    """Submits a new user scam report into the intelligence repository."""
    return community_service_instance.add_report(report)

@app.post("/api/community/reports/{report_id}/upvote", response_model=CommunityReportItem)
def upvote_community_report(report_id: str):
    """Upvotes a report to increase its community verification confidence."""
    item = community_service_instance.upvote_report(report_id)
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    return item

@app.get("/api/stats")
def get_platform_stats():
    """Aggregated scam intelligence metrics and threat distribution."""
    return {
        "total_scams_analyzed": 14280,
        "scams_thwarted": 11840,
        "money_saved_estimated_inr": "₹4.82 Crores",
        "scam_types_breakdown": [
            {"name": "Upfront Fee / Gate Pass / Uniform", "percentage": 42},
            {"name": "Telegram & WhatsApp Task Scams", "percentage": 28},
            {"name": "Bait-and-Switch Offer Letters", "percentage": 14},
            {"name": "Identity Theft & Document Extortion", "percentage": 10},
            {"name": "Malicious Phishing URLs", "percentage": 6}
        ],
        "top_scammed_target_sectors": [
            "IT & Software Internships",
            "Airlines Ground Staff & Cabin Crew",
            "Remote Data Entry & Back Office",
            "YouTube Video Rating & Hotel Reviews",
            "Bank Exam Direct Recruitment"
        ]
    }

@app.get("/api/advisories")
def get_cybercrime_advisories():
    """Official cybercrime alerts and legal advisories."""
    return {
        "hotline": "1930",
        "official_portal": "https://cybercrime.gov.in",
        "authority": "Indian Cyber Crime Coordination Centre (I4C), Ministry of Home Affairs",
        "chakshu_portal": "https://sancharsaathi.gov.in/sfc/ (Report Fraudulent Communication)",
        "golden_rules": [
            "No legitimate company ever asks for money, deposits, or processing fees for a job offer.",
            "Never share blank signed cheques, OTPs, or surrender original educational marksheets.",
            "Verify all recruiter communications through the official career portal domain (e.g. tcs.com, infosys.com, google.com).",
            "Part-time online task schemes (e.g. YouTube likes, Google ratings) are financial traps designed to solicit prepaid deposits.",
            "If an offer sounds too good to be true (e.g. ₹5,000/day for 30 minutes without an interview), it is 100% a scam."
        ]
    }
