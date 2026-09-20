"""
ForensicChain AI Smart Warrant Advisor v1.0
Analyzes authorized case progress, remaining validity, and incomplete workflow stages
to generate advisory warrant extension recommendations for Police & Court Authority.
Strictly advisory:
- Only authorized human users can request / approve extensions
- AI never automatically extends or approves warrants
- Clearly designated as "AI Recommendation", never "AI Decision"
"""

import os
import sys
import json
from datetime import datetime, timezone

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

try:
    import database as db
except ImportError:
    from backend import database as db


def parse_dt(val):
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        import dateutil.parser
        return dateutil.parser.parse(str(val))
    except Exception:
        return None


def calculate_evidence_lifecycle_stages(ev, custody_logs):
    """
    Computes completed stages out of 9 standard ForensicChain lifecycle stages:
    1: Seizure Initiated / Uploaded
    2: Witness Attested
    3: Collected
    4: Transferred
    5: Forensic Analysis Started
    6: Forensic Analysis Completed
    7: Verified
    8: Presented to Court
    9: Stored / Sealed
    """
    completed = set()
    completed.add(1) # Evidence exists

    if ev.get("witness_signed_at") or ev.get("witness_signed_by"):
        completed.add(2)

    status = (ev.get("status") or "").lower()
    if ev.get("is_sealed") or status in {"sealed", "stored", "released", "destroyed"}:
        completed.update([1, 2, 3, 4, 5, 6, 7, 8, 9])
        return len(completed)

    for l in custody_logs:
        act = (l.get("action") or "").lower()
        if "attest" in act:
            completed.add(2)
        elif "collect" in act:
            completed.add(3)
        elif "transfer" in act:
            completed.add(4)
        elif "analysis started" in act:
            completed.add(5)
        elif "analysis completed" in act or "analyzed" in act:
            completed.add(6)
        elif "verif" in act or "tamper check" in act:
            completed.add(7)
        elif "court" in act or "present" in act:
            completed.add(8)
        elif "seal" in act or "store" in act:
            completed.add(9)

    if status == "verified":
        completed.add(7)
    elif status in {"transferred", "in_transit"}:
        completed.add(4)
    elif status == "collected":
        completed.add(3)

    return len(completed)


def generate_warrant_recommendation(warrant_number, user=None):
    """
    Analyzes case evidence, pending workflow stages, and remaining validity window
    for a given warrant number. Produces an objective AI Recommendation.
    """
    warrant_number = (warrant_number or "").strip()
    if not warrant_number:
        return None, "warrant_number is required", 400

    if user and user.get("role") == "witness":
        return None, "Access Denied: Witness role has no access to Smart Warrants", 403

    warrant = db.get_warrant_by_number(warrant_number)
    if not warrant:
        return None, f"Smart Warrant '{warrant_number}' not found", 404

    case_id = warrant.get("case_id") or ""
    now = datetime.now()
    valid_until = parse_dt(warrant.get("valid_until"))

    # Remaining time calculation
    if valid_until:
        if valid_until.tzinfo is not None and now.tzinfo is None:
            now = datetime.now(timezone.utc)
        remaining_seconds = int((valid_until - now).total_seconds())
    else:
        remaining_seconds = 0

    is_expired = remaining_seconds <= 0
    remaining_hours = max(0.0, round(remaining_seconds / 3600.0, 1))

    # Fetch case evidence
    evidence_list = db.get_evidence_by_case_id(case_id) if case_id else []
    total_evidence = len(evidence_list)

    pending_evidence = 0
    pending_verification = 0
    pending_court_review = 0
    total_stages_completed = 0
    total_expected_stages = max(1, total_evidence * 9)

    for ev in evidence_list:
        logs = db.get_custody_logs(ev["evidence_id"])
        stages_done = calculate_evidence_lifecycle_stages(ev, logs)
        total_stages_completed += stages_done

        st = (ev.get("status") or "").lower()
        if st not in {"verified", "sealed", "presented"}:
            pending_evidence += 1

        if st != "verified" and not ev.get("is_sealed"):
            pending_verification += 1

        if not ev.get("is_sealed") and "court" not in st and "presented" not in st:
            pending_court_review += 1

    if total_evidence > 0:
        workflow_completion_pct = round((total_stages_completed / total_expected_stages) * 100.0, 1)
        workflow_completion_pct = min(100.0, max(0.0, workflow_completion_pct))
    else:
        workflow_completion_pct = 0.0

    incomplete_stages_count = max(0, total_expected_stages - total_stages_completed)

    # Determine AI Recommendation and Reason
    if is_expired:
        if incomplete_stages_count > 0 or total_evidence > 0:
            recommendation = "Extension may be required."
            reason = "The current warrant has expired while several forensic workflow stages (including pending verification/court review) remain incomplete."
            confidence = "high"
        else:
            recommendation = "Extension not currently indicated."
            reason = "Warrant has expired but all case evidentiary workflow stages have been completed."
            confidence = "high"
    elif remaining_seconds < 172800 and (pending_evidence > 0 or pending_verification > 0 or workflow_completion_pct < 85.0):
        recommendation = "Extension may be required."
        reason = "Several forensic workflow stages remain incomplete and the current warrant has limited remaining validity."
        confidence = "high" if remaining_seconds < 86400 else "medium"
    elif remaining_seconds < 86400:
        recommendation = "Extension may be required."
        reason = f"Warrant expires within {remaining_hours} hours. Active investigation protocol warrants extension request if operational activity is ongoing."
        confidence = "medium"
    else:
        recommendation = "Extension not currently indicated."
        reason = f"Current warrant remaining validity ({remaining_hours}h remaining) is sufficient for active case workflow status ({workflow_completion_pct}% completion)."
        confidence = "medium"

    # Current expiry formatted display
    if valid_until:
        current_expiry_str = valid_until.strftime("%d %b %Y %H:%M:%S UTC")
    else:
        current_expiry_str = "Information not available."

    # Check existing extension requests for final human decision state
    ext_requests = db.get_warrant_extension_requests(warrant_number=warrant_number)
    pending_req = next((r for r in ext_requests if r.get("status") == "pending"), None)
    latest_decision = "pending" if pending_req else (ext_requests[0].get("status") if ext_requests else "none")

    relevant_features = {
        "warrant_number": warrant_number,
        "case_id": case_id or "Information not available.",
        "total_evidence_items": total_evidence,
        "pending_evidence_items": pending_evidence,
        "pending_verification_items": pending_verification,
        "pending_court_review_items": pending_court_review,
        "workflow_completion_pct": workflow_completion_pct,
        "incomplete_workflow_stages": incomplete_stages_count,
        "remaining_seconds": remaining_seconds,
        "remaining_hours": remaining_hours,
        "is_expired": is_expired
    }

    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    model_version = "v1.0-warrant-advisor"

    # Save recommendation in database
    db.save_warrant_ai_recommendation(
        warrant_number=warrant_number,
        case_id=case_id,
        recommendation=recommendation,
        confidence=confidence,
        reason=reason,
        workflow_completion_pct=workflow_completion_pct,
        features_json=json.dumps(relevant_features),
        model_version=model_version,
        final_human_decision=latest_decision
    )

    payload = {
        "warrant_number": warrant_number,
        "case_id": case_id or "Information not available.",
        "current_expiry": current_expiry_str,
        "workflow_completion_pct": workflow_completion_pct,
        "pending": {
            "evidence_items": pending_evidence,
            "forensic_verification": pending_verification,
            "court_review": pending_court_review,
            "incomplete_stages": incomplete_stages_count
        },
        "ai_recommendation": recommendation,
        "confidence": confidence,
        "reason": reason,
        "relevant_features": relevant_features,
        "model_version": model_version,
        "recommendation_timestamp": timestamp_str,
        "final_human_decision": latest_decision,
        "pending_extension_request": pending_req,
        "disclaimer": "AI Recommendation only — Not a legal decision. The Court Authority retains sole constitutional authority to approve or reject warrant extensions."
    }

    return payload, None, 200
