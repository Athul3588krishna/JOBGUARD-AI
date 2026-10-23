import re
from typing import Dict, Any, List, Tuple, Optional
from app.models.schemas import EvidenceItem, Severity
from app.services.nlp_analyzer import MONEY_REGEX

class ConsistencyEngine:
    @staticmethod
    def _extract_number(money_str: str) -> Optional[float]:
        """Extracts numerical amount from string."""
        if not money_str:
            return None
        nums = re.findall(r'[\d,]+(?:\.\d+)?', str(money_str))
        if nums:
            try:
                return float(nums[0].replace(",", ""))
            except ValueError:
                return None
        return None

    def compare_job_and_offer(
        self,
        job_title: str,
        job_company: str,
        job_description: str,
        job_salary: str,
        offer_role: str,
        offer_company: str,
        offer_text: str,
        offer_salary: str,
        offer_deposit: str = ""
    ) -> Dict[str, Any]:
        """
        Cross-examines job advertisement details vs received offer letter or recruiter agreement.
        Returns contradiction scores, evidence, warnings, and detailed comparison matrix.
        """
        inconsistency_score = 0.0
        evidence: List[EvidenceItem] = []
        major_warnings: List[str] = []
        minor_cautions: List[str] = []
        matrix: List[Dict[str, Any]] = []

        # 1. Company Name Consistency
        norm_job_comp = job_company.lower().strip() if job_company else ""
        norm_offer_comp = offer_company.lower().strip() if offer_company else ""
        
        comp_status = "MATCH"
        if norm_job_comp and norm_offer_comp:
            if norm_job_comp not in norm_offer_comp and norm_offer_comp not in norm_job_comp:
                comp_status = "MISMATCH"
                inconsistency_score += 45.0
                evidence.append(EvidenceItem(
                    category="Cross-Document Inconsistency",
                    severity=Severity.HIGH,
                    title="Company Name Contradiction",
                    explanation=f"Applied to '{job_company}', but offer letter is issued on behalf of '{offer_company}'. Common in third-party scam agencies.",
                    matched_phrase=f"{job_company} vs {offer_company}"
                ))
                major_warnings.append(f"Entity Contradiction: Job posting company '{job_company}' differs from offer issuer '{offer_company}'")
        
        matrix.append({
            "field": "Company Name",
            "job_posting": job_company or "Not specified",
            "offer_letter": offer_company or "Not specified",
            "status": comp_status
        })

        # 2. Role / Designation Consistency
        norm_job_role = job_title.lower().strip() if job_title else ""
        norm_offer_role = offer_role.lower().strip() if offer_role else ""

        role_status = "MATCH"
        if norm_job_role and norm_offer_role:
            # Check for dramatic inflation (Intern -> Senior Architect / VP)
            is_intern_job = any(w in norm_job_role for w in ["intern", "trainee", "fresher", "junior", "assistant"])
            is_senior_offer = any(w in norm_offer_role for w in ["senior", "lead", "architect", "manager", "director", "head"])

            if is_intern_job and is_senior_offer:
                role_status = "SUSPICIOUS_INFLATION"
                inconsistency_score += 50.0
                evidence.append(EvidenceItem(
                    category="Role Escalation",
                    severity=Severity.CRITICAL,
                    title="Suspicious Role Inflation (Bait-and-Switch)",
                    explanation=f"Applied for an entry-level position '{job_title}', but received an offer designated as '{offer_role}'. Scammers inflate titles to justify high advance deposit requests.",
                    matched_phrase=f"{job_title} -> {offer_role}"
                ))
                major_warnings.append(f"Title Escalation: Applied for '{job_title}', offered senior role '{offer_role}' without qualification")
            elif norm_job_role not in norm_offer_role and norm_offer_role not in norm_job_role:
                role_status = "MISMATCH"
                inconsistency_score += 25.0
                minor_cautions.append(f"Role Variation: Advertised title '{job_title}' differs from offer letter '{offer_role}'")

        matrix.append({
            "field": "Designation / Role",
            "job_posting": job_title or "Not specified",
            "offer_letter": offer_role or "Not specified",
            "status": role_status
        })

        # 3. Salary & Compensation Comparison
        job_sal_val = self._extract_number(job_salary)
        offer_sal_val = self._extract_number(offer_salary)
        
        sal_status = "MATCH"
        if job_sal_val and offer_sal_val:
            # If offer is more than 3x the advertised salary without explanation
            if offer_sal_val > (job_sal_val * 3.5):
                sal_status = "EXTREME_INFLATION"
                inconsistency_score += 55.0
                evidence.append(EvidenceItem(
                    category="Financial Anomaly",
                    severity=Severity.CRITICAL,
                    title="Astronomical Salary Discrepancy",
                    explanation=f"Advertised salary was {job_salary}, but offer letter promises {offer_salary} (over 300% inflation). Known scam bait technique.",
                    matched_phrase=f"{job_salary} vs {offer_salary}"
                ))
                major_warnings.append(f"Bait-and-Switch: Offer salary ({offer_salary}) is unrealistically higher than advertised ({job_salary})")
            elif offer_sal_val < (job_sal_val * 0.4):
                sal_status = "SIGNIFICANT_DROP"
                inconsistency_score += 25.0
                minor_cautions.append(f"Compensation Drop: Offer salary ({offer_salary}) is dramatically lower than advertised ({job_salary})")

        matrix.append({
            "field": "Salary / CTC",
            "job_posting": job_salary or "Not specified",
            "offer_letter": offer_salary or "Not specified",
            "status": sal_status
        })

        # 4. Deposit & Upfront Fee Appearance
        has_job_fee = bool(re.search(r'\b(fee|deposit|charge|cost)\b', job_description, re.IGNORECASE))
        has_offer_fee = bool(re.search(r'\b(fee|deposit|charge|refundable|laptop\s+dispatch)\b', offer_text, re.IGNORECASE)) or bool(offer_deposit)

        fee_status = "CONSISTENT"
        if not has_job_fee and has_offer_fee:
            fee_status = "SURPRISE_FEE_INTRODUCED"
            inconsistency_score += 65.0
            evidence.append(EvidenceItem(
                category="Surprise Financial Demand",
                severity=Severity.CRITICAL,
                title="Hidden Payment Introduced Post-Selection",
                explanation="Original job listing made zero mention of fees or deposits, but the offer letter introduces a mandatory payment clause. This is a trademark employment scam tactic.",
                matched_phrase=offer_deposit or "Payment introduced in offer"
            ))
            major_warnings.append("CRITICAL WARNING: Offer introduces mandatory payment/deposit not present in original job posting")

        matrix.append({
            "field": "Advance Fees / Deposit",
            "job_posting": "None mentioned",
            "offer_letter": offer_deposit or ("Fee detected in clauses" if has_offer_fee else "None"),
            "status": fee_status
        })

        contradiction_risk = min(100.0, max(0.0, inconsistency_score))

        return {
            "contradiction_risk": contradiction_risk,
            "evidence": evidence,
            "major_warnings": major_warnings,
            "minor_cautions": minor_cautions,
            "comparison_matrix": matrix,
            "overall_consistency": "HIGH" if contradiction_risk < 25 else ("MODERATE" if contradiction_risk < 55 else "CONTRADICTORY")
        }
