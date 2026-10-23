import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from app.models.schemas import CommunityReportCreate, CommunityReportItem

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
REPORTS_FILE = os.path.join(DATA_DIR, "community_reports.json")

SEED_REPORTS = [
    {
        "id": "REP-8041",
        "company_name": "Tata Consultancy Services (Impersonated)",
        "job_title": "Graduate Trainee Engineer - 2026 Batch",
        "scam_type": "Upfront Fee",
        "scammer_email": "tcs.careers.desk@gmail.com",
        "scammer_phone": "+91 98765 43210",
        "scammer_telegram": "@tcs_campus_hr",
        "scam_url": "http://tcs-careers-interviewpass.xyz",
        "description": "Received an email claiming direct selection for TCS without technical interview. Sent an offer letter requesting ₹6,500 for 'Medical Examination & Security Gatepass' via Google Pay UPI.",
        "money_demanded": 6500.0,
        "evidence_text": "Please deposit Rs. 6500 to UPI ID tcs.hrverification@oksbi within 24 hours to generate your employee badge.",
        "reported_at": "2026-03-12 14:20",
        "upvotes": 47,
        "verification_status": "COMMUNITY_VERIFIED"
    },
    {
        "id": "REP-8042",
        "company_name": "Global Media Ads Agency",
        "job_title": "Part-Time YouTube Video Liker & Reviewer",
        "scam_type": "Telegram Task Scam",
        "scammer_email": "hr@globalmedia-partners.top",
        "scammer_phone": "+62 821 5543 9012",
        "scammer_telegram": "@global_task_recharge",
        "scam_url": "https://global-media-task.vip/recharge",
        "description": "WhatsApp message from Indonesian prefix (+62). Paid ₹150 for liking 3 YouTube videos. Then added to a Telegram VIP group and demanded ₹3,000 recharge to unlock level 2 payments.",
        "money_demanded": 3000.0,
        "evidence_text": "Complete Task 4 to receive 30% commission bonus. Minimum wallet recharge required: ₹3000.",
        "reported_at": "2026-03-18 10:15",
        "upvotes": 112,
        "verification_status": "COMMUNITY_VERIFIED"
    },
    {
        "id": "REP-8043",
        "company_name": "Wipro Technologies (Fake Offer)",
        "job_title": "Junior Python / React Developer Intern",
        "scam_type": "Fake MNC Offer",
        "scammer_email": "wipro.onboarding@consultant.com",
        "scammer_phone": "+91 88761 23450",
        "scammer_telegram": "@wipro_internship_team",
        "scam_url": "http://wipro-careers-portal.link",
        "description": "Sent a PDF offer letter with blurry Wipro logo. Stated that a work laptop (MacBook Pro) will be dispatched only after applicant deposits ₹8,500 courier and insurance charge.",
        "money_demanded": 8500.0,
        "evidence_text": "Laptop courier insurance charge of INR 8,500 is 100% refundable upon first month stipend disbursement.",
        "reported_at": "2026-03-24 16:45",
        "upvotes": 89,
        "verification_status": "COMMUNITY_VERIFIED"
    },
    {
        "id": "REP-8044",
        "company_name": "IndiGo Airlines (Fake Ground Staff Racket)",
        "job_title": "Airport Customer Support & Ground Operations",
        "scam_type": "Upfront Fee",
        "scammer_email": "indigo.airport.hiring@yahoo.com",
        "scammer_phone": "+91 97112 34981",
        "scammer_telegram": None,
        "scam_url": "http://indigo-airports-pass.site",
        "description": "SMS promised ₹35,000 monthly salary for airport ground staff with 12th pass qualification. Demanded ₹2,500 for 'Airport Security Clearance Uniform Badge'.",
        "money_demanded": 2500.0,
        "evidence_text": "Direct recruitment in IGI Airport Delhi. No exam. Pay uniform fee Rs. 2500.",
        "reported_at": "2026-04-02 09:30",
        "upvotes": 64,
        "verification_status": "COMMUNITY_VERIFIED"
    },
    {
        "id": "REP-8045",
        "company_name": "Amazon India (Work From Home Typing)",
        "job_title": "Data Entry & Product Reviewer",
        "scam_type": "Identity Theft",
        "scammer_email": "amazon.wfh.recruitment@proton.me",
        "scammer_phone": "+91 91234 56789",
        "scammer_telegram": "@amazon_wfh_desk",
        "scam_url": "https://amazon-careers-verify.buzz",
        "description": "Demanded scanned copy of Aadhaar card, PAN card, and a blank cheque with signature for 'salary account opening' before any interview.",
        "money_demanded": 0.0,
        "evidence_text": "Upload cancelled cheque with signature and Aadhaar front/back for immediate appointment letter.",
        "reported_at": "2026-04-10 11:00",
        "upvotes": 78,
        "verification_status": "COMMUNITY_VERIFIED"
    }
]

class CommunityService:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(REPORTS_FILE):
            self._save_reports(SEED_REPORTS)

    def _load_reports(self) -> List[Dict[str, Any]]:
        try:
            with open(REPORTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return SEED_REPORTS

    def _save_reports(self, reports: List[Dict[str, Any]]):
        with open(REPORTS_FILE, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)

    def get_all_reports(self, search: Optional[str] = None, scam_type: Optional[str] = None) -> List[CommunityReportItem]:
        reports = self._load_reports()
        if search:
            query = search.lower().strip()
            reports = [
                r for r in reports if
                query in r.get("company_name", "").lower() or
                query in r.get("job_title", "").lower() or
                query in r.get("scammer_email", "").lower() or
                query in r.get("scammer_phone", "").lower() or
                query in r.get("scammer_telegram", "").lower() or
                query in r.get("description", "").lower()
            ]
        if scam_type and scam_type != "All":
            reports = [r for r in reports if r.get("scam_type", "").lower() == scam_type.lower()]
        
        return [CommunityReportItem(**r) for r in reports]

    def add_report(self, report_in: CommunityReportCreate) -> CommunityReportItem:
        reports = self._load_reports()
        new_item = {
            "id": f"REP-{uuid.uuid4().hex[:6].upper()}",
            "company_name": report_in.company_name,
            "job_title": report_in.job_title,
            "scam_type": report_in.scam_type,
            "scammer_email": report_in.scammer_email or "",
            "scammer_phone": report_in.scammer_phone or "",
            "scammer_telegram": report_in.scammer_telegram or "",
            "scam_url": report_in.scam_url or "",
            "description": report_in.description,
            "money_demanded": report_in.money_demanded or 0.0,
            "evidence_text": report_in.evidence_text or "",
            "reported_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "upvotes": 1,
            "verification_status": "COMMUNITY_VERIFIED"
        }
        reports.insert(0, new_item)
        self._save_reports(reports)
        return CommunityReportItem(**new_item)

    def upvote_report(self, report_id: str) -> Optional[CommunityReportItem]:
        reports = self._load_reports()
        for r in reports:
            if r["id"] == report_id:
                r["upvotes"] = r.get("upvotes", 0) + 1
                self._save_reports(reports)
                return CommunityReportItem(**r)
        return None
