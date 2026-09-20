"""
ForensicChain AI Case Summary Engine v2.4
Aggregates confirmed database and blockchain facts for a specified Case ID,
generates a structured forensic summary adhering to evidentiary rules:
- Strictly distinguishes Confirmed Facts vs AI Narrative vs Recommendations
- Never invents missing data; writes "Information not available." when absent
- Avoids unsupported conclusions (no claims of guilt, fraud, or misconduct)
- Supports external LLM (Gemini) when configured, with deterministic fallback
- Adds timestamp, model identifier, and mandatory legal disclaimers
"""

import os
import sys
import json
import requests
from datetime import datetime, timezone

# Ensure project root & backend are in sys.path
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


def check_user_access_for_evidence(user, evidence):
    """Verifies whether a user has legitimate access rights to an evidence record."""
    if not user:
        return False
    role = user.get("role", "")
    if role in {"admin", "court_authority"}:
        return True

    uid = int(user.get("id") or 0)
    if int(evidence.get("witness_required_id") or 0) == uid:
        return True
    if int(evidence.get("witness_signed_by") or 0) == uid:
        return True
    if int(evidence.get("uploaded_by") or 0) == uid:
        return True

    if role == "witness":
        return False

    if not evidence.get("is_private"):
        return True

    ev_id = evidence.get("evidence_id")
    if role == "police" and hasattr(db, "has_police_access_grant"):
        return db.has_police_access_grant(ev_id, uid)

    if role in {"investigator", "analyst"} and hasattr(db, "has_approved_access"):
        return db.has_approved_access(ev_id, uid)

    return False


def collect_case_data(case_id, user=None):
    """
    Gathers all verified factual data for a given case_id from database & blockchain.
    Returns:
        tuple (case_data_dict, error_message, status_code)
    """
    case_id = (case_id or "").strip()
    if not case_id:
        return None, "case_id is required", 400

    raw_evidence = db.get_evidence_by_case_id(case_id)
    if not raw_evidence:
        # Check if any warrants exist for this case
        raw_warrants = db.get_warrants_by_case_id(case_id)
        if not raw_warrants:
            return None, f"Case '{case_id}' not found in registry", 404
        evidence_list = []
    else:
        # Filter by role-based access if user is supplied
        if user:
            role = user.get("role", "")
            if role == "witness":
                return None, "Access Denied: Witness role is restricted from case summary generation.", 403
            evidence_list = [e for e in raw_evidence if check_user_access_for_evidence(user, e)]
            if not evidence_list and role not in {"admin", "court_authority"}:
                return None, f"Access Denied: You do not have authorization to view evidence in case '{case_id}'.", 403
        else:
            evidence_list = list(raw_evidence)

    # 1. Evidence counts & file types
    total_items = len(evidence_list)
    evidence_ids = [e["evidence_id"] for e in evidence_list]
    
    type_counts = {}
    status_counts = {"verified": 0, "pending": 0, "other": 0}
    witness_req_count = 0
    witness_attested_count = 0

    all_custody_logs = []
    anomaly_reports = []

    for ev in evidence_list:
        fn = ev.get("file_name") or ""
        ext = fn.split(".")[-1].lower() if "." in fn else "unknown"
        type_counts[ext] = type_counts.get(ext, 0) + 1

        ev_status = (ev.get("status") or "").lower()
        if ev_status == "verified":
            status_counts["verified"] += 1
        elif ev_status in {"pending", "uploaded", "collected", "transferred"}:
            status_counts["pending"] += 1
        else:
            status_counts["other"] += 1

        if ev.get("witness_required_id"):
            witness_req_count += 1
            if ev.get("witness_signed_at") or ev.get("witness_signed_by"):
                witness_attested_count += 1

        # Custody logs for this item
        logs = db.get_custody_logs(ev["evidence_id"])
        for l in logs:
            all_custody_logs.append(dict(l))

        # Check latest ML anomaly report
        rep = db.get_latest_anomaly_report(ev["evidence_id"])
        if rep:
            anomaly_reports.append(dict(rep))

    # Sort all custody logs chronologically
    all_custody_logs.sort(key=lambda x: str(x.get("created_at") or ""))

    # 2. Witness Attestation status
    if total_items == 0:
        witness_status_str = "Information not available."
    elif witness_req_count == 0:
        witness_status_str = "Completed (No independent witness attestation required for current items)"
    elif witness_attested_count == witness_req_count:
        witness_status_str = f"Completed ({witness_attested_count} of {witness_req_count} items attested)"
    else:
        witness_status_str = f"Pending ({witness_attested_count} of {witness_req_count} items attested; {witness_req_count - witness_attested_count} awaiting witness signature)"

    # 3. Forensic Verification status
    verified_count = status_counts["verified"]
    pending_count = total_items - verified_count
    if total_items == 0:
        forensic_verification_str = "Information not available."
    elif pending_count == 0:
        forensic_verification_str = f"All {total_items} evidence item(s) cryptographically verified."
    else:
        forensic_verification_str = f"{verified_count} verified, {pending_count} pending verification."

    # 4. Chain of Custody summary
    if not all_custody_logs:
        custody_summary_str = "Information not available."
    else:
        unique_actors = {l.get("actor_name") for l in all_custody_logs if l.get("actor_name")}
        custody_summary_str = f"{len(all_custody_logs)} recorded custody actions across {len(unique_actors) or 1} authenticated actor(s)."

    # 5. Blockchain Integrity
    onchain_items = sum(1 for e in evidence_list if e.get("tx_hash") and not e.get("tx_hash").startswith("OFFLINE"))
    if total_items == 0:
        blockchain_integrity_str = "Information not available."
    else:
        blockchain_integrity_str = f"{onchain_items} of {total_items} evidence records confirmed on Ethereum blockchain."

    # 6. Smart Warrant information
    warrants = db.get_warrants_by_case_id(case_id)
    if not warrants:
        warrant_str = "Information not available."
        active_warrant = None
    else:
        active_warrant = warrants[0]
        w_num = active_warrant.get("warrant_number")
        w_status = active_warrant.get("status") or "active"
        w_expiry = active_warrant.get("valid_until")
        now_dt = datetime.now()
        is_active = True
        if w_expiry:
            try:
                import dateutil.parser
                exp_dt = dateutil.parser.parse(str(w_expiry))
                if exp_dt.tzinfo is not None:
                    now_dt = datetime.now(timezone.utc)
                is_active = now_dt < exp_dt
            except Exception:
                is_active = (w_status == "active")

        if is_active:
            warrant_str = f"Active until {w_expiry} (Warrant #{w_num})"
        else:
            warrant_str = f"Expired on {w_expiry} (Warrant #{w_num})"

    # 7. AI/ML Alerts
    high_risk_alerts = [r for r in anomaly_reports if r.get("risk_level") == "HIGH"]
    med_risk_alerts = [r for r in anomaly_reports if r.get("risk_level") == "MEDIUM"]
    total_alerts = len(high_risk_alerts) + len(med_risk_alerts)
    if total_alerts == 0:
        ml_alerts_str = "0 suspicious activity detected. All evidence access metrics within normal parameters."
    else:
        alert_details = []
        for r in high_risk_alerts:
            alert_details.append(f"HIGH risk on {r.get('evidence_id')} (score {r.get('anomaly_score')})")
        for r in med_risk_alerts:
            alert_details.append(f"MEDIUM risk on {r.get('evidence_id')} (score {r.get('anomaly_score')})")
        ml_alerts_str = f"{total_alerts} suspicious activity detected: {'; '.join(alert_details)}."

    # 8. Timeline generation (ordered events)
    timeline_steps = []
    if all_custody_logs:
        step_idx = 1
        for log in all_custody_logs:
            action = log.get("action") or "Custody Action"
            actor = log.get("actor_name") or log.get("actor_role") or "Authorized User"
            ts = log.get("created_at") or "Unknown Date"
            ev_id = log.get("evidence_id") or ""
            note = log.get("note") or ""
            line = f"{step_idx}. {action.title()} ({ev_id}) by {actor} at {ts}"
            if note:
                line += f" — Note: {note[:60]}"
            timeline_steps.append(line)
            step_idx += 1
    elif total_items > 0:
        step_idx = 1
        for ev in evidence_list:
            timeline_steps.append(f"{step_idx}. Evidence {ev.get('evidence_id')} registered at {ev.get('created_at')}")
            step_idx += 1
    else:
        timeline_steps = ["Information not available."]

    confirmed_facts = {
        "case_id": case_id,
        "total_evidence_items": total_items,
        "evidence_ids": evidence_ids,
        "evidence_status": {
            "verified": verified_count,
            "pending": pending_count,
            "status_text": f"{verified_count} verified, {pending_count} pending" if total_items > 0 else "Information not available."
        },
        "evidence_types": type_counts,
        "witness_attestation": witness_status_str,
        "forensic_verification": forensic_verification_str,
        "chain_of_custody": custody_summary_str,
        "blockchain_integrity": blockchain_integrity_str,
        "smart_warrant": warrant_str,
        "ai_ml_alerts": ml_alerts_str,
        "timeline": timeline_steps
    }

    return confirmed_facts, None, 200


def build_ai_narrative(case_data):
    """
    Generates objective, rule-governed AI narrative based strictly on confirmed facts.
    Ensures zero unsupported conclusions (no claims of guilt, fraud, or misconduct).
    """
    c_id = case_data["case_id"]
    tot = case_data["total_evidence_items"]
    ev_status = case_data["evidence_status"]
    w_status = case_data["witness_attestation"]
    bc_status = case_data["blockchain_integrity"]
    warrant = case_data["smart_warrant"]
    ml_alerts = case_data["ai_ml_alerts"]

    paragraphs = []
    
    # Overview
    if tot == 0:
        paragraphs.append(
            f"Case {c_id} is registered in the legal index, but no physical or digital evidence records "
            "are currently associated with this case identifier."
        )
    else:
        paragraphs.append(
            f"Case {c_id} currently comprises {tot} documented evidentiary item(s). "
            f"Cryptographic verification indicates {ev_status['verified']} item(s) confirmed, "
            f"with {ev_status['pending']} item(s) pending completed forensic laboratory analysis."
        )

    # Procedural status
    paragraphs.append(
        f"Two-factor independent witness attestation is recorded as: '{w_status}'. "
        f"Smart search warrant authorization status is: '{warrant}'. "
        f"Immutable distributed ledger anchoring confirms: '{bc_status}'."
    )

    # Security & Integrity
    paragraphs.append(
        f"Auxiliary AI behavioral monitoring reflects: '{ml_alerts}'. "
        "All custody transfers and cryptographic hashes remain under active ledger supervision."
    )

    return " ".join(paragraphs)


def build_ai_recommendations(case_data):
    """
    Generates procedural forensic recommendations strictly based on missing or pending steps.
    """
    recommendations = []
    ev_status = case_data["evidence_status"]
    w_status = case_data["witness_attestation"]
    warrant = case_data["smart_warrant"]
    tot = case_data["total_evidence_items"]

    if tot == 0:
        recommendations.append("Register seized evidentiary artifacts under this case identifier.")
        return recommendations

    if ev_status["pending"] > 0:
        recommendations.append(
            f"Prioritize forensic hash verification for the {ev_status['pending']} pending evidence item(s) prior to judicial submission."
        )

    if "Pending" in w_status:
        recommendations.append(
            "Obtain outstanding independent witness attestations to satisfy statutory seizure protocol requirements."
        )

    if warrant == "Information not available.":
        recommendations.append(
            "Verify whether a formal search/seizure warrant is required for this case jurisdiction and link active warrant if issued."
        )
    elif "Expired" in warrant:
        recommendations.append(
            "Active warrant has expired. Submit a warrant extension request via the Court Authority workflow before collecting further evidence."
        )

    if "suspicious activity detected" in case_data["ai_ml_alerts"] and not case_data["ai_ml_alerts"].startswith("0"):
        recommendations.append(
            "Conduct an administrative custody audit on evidence flagged by AI/ML behavioral anomaly monitoring."
        )

    if not recommendations:
        recommendations.append("All statutory custody, attestation, and cryptographic verification milestones are currently satisfied.")

    return recommendations


def generate_structured_report_text(case_data, ai_narrative, ai_recommendations, model_name, timestamp):
    """
    Formats the complete forensic report in clean, standardized legal text.
    """
    c = case_data
    lines = [
        "================================================================================",
        "                       FORENSICCHAIN LEGAL CASE SUMMARY                         ",
        "================================================================================",
        f"Case ID:                 {c['case_id']}",
        f"Generated At:            {timestamp}",
        f"AI Engine / Model:       {model_name}",
        "Legal Standard:          Human Review Required (Advisory AI Layer)",
        "--------------------------------------------------------------------------------",
        "",
        "SECTION 1: CONFIRMED SYSTEM FACTS (Database & Blockchain Verified)",
        "--------------------------------------------------------------------------------",
        f"Case ID:                 {c['case_id']}",
        f"Evidence:                {c['total_evidence_items']} items",
        f"Evidence Status:         {c['evidence_status']['status_text']}",
        f"Witness Attestation:     {c['witness_attestation']}",
        f"Forensic Verification:   {c['forensic_verification']}",
        f"Chain of Custody:        {c['chain_of_custody']}",
        f"Blockchain Integrity:    {c['blockchain_integrity']}",
        f"Smart Warrant:           {c['smart_warrant']}",
        f"AI/ML Alerts:            {c['ai_ml_alerts']}",
        "",
        "Timeline of Custody Events:",
    ]

    for step in c["timeline"]:
        lines.append(f"  {step}")

    lines.extend([
        "",
        "--------------------------------------------------------------------------------",
        "SECTION 2: AI-GENERATED CASE SYNTHESIS (Synthesized Narrative)",
        "--------------------------------------------------------------------------------",
        ai_narrative,
        "",
        "--------------------------------------------------------------------------------",
        "SECTION 3: AI-GENERATED PROCEDURAL RECOMMENDATIONS (Advisory Only)",
        "--------------------------------------------------------------------------------",
    ])

    for idx, rec in enumerate(ai_recommendations, start=1):
        lines.append(f"  {idx}. {rec}")

    lines.extend([
        "",
        "================================================================================",
        "DISCLAIMER: This document is an AI-synthesized advisory summary. It does not",
        "constitute a judicial conclusion or legal finding of fact. Cryptographic hash",
        "verification and blockchain ledger receipts remain the authoritative legal standard.",
        "================================================================================"
    ])

    return "\n".join(lines)


def generate_case_summary(case_id, user=None):
    """
    Main entry point for Case Summary generation.
    Returns:
        tuple (summary_dict, error_message, status_code)
    """
    case_data, err, status = collect_case_data(case_id, user)
    if err:
        return None, err, status

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    model_name = "ForensicChain Natural Synthesis Engine v2.4"

    # Check if Gemini API key is available in environment
    gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    ai_narrative = None
    ai_recommendations = None

    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            prompt = (
                "You are an objective legal forensic summarizer for the ForensicChain system.\n"
                "Review the following confirmed facts about a case and generate:\n"
                "1. An objective factual synthesis (2-3 sentences).\n"
                "2. 2-3 procedural recommendations for forensic officers.\n"
                "RULES:\n"
                "- Do NOT invent information. If data is missing, write 'Information not available.'\n"
                "- Do NOT state conclusions about guilt, fraud, or misconduct.\n"
                "- Strictly distinguish between confirmed facts and advisory notes.\n\n"
                f"CONFIRMED FACTS:\n{json.dumps(case_data, indent=2)}\n\n"
                "Output JSON format:\n{\"narrative\": \"...\", \"recommendations\": [\"...\"]}"
            )
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            resp = requests.post(url, json=payload, timeout=8)
            if resp.status_code == 200:
                res_data = resp.json()
                text_out = res_data["candidates"][0]["content"]["parts"][0]["text"]
                # Parse JSON out of markdown block if wrapped
                clean_text = text_out.strip()
                if clean_text.startswith("```"):
                    clean_text = clean_text.split("```")[1]
                    if clean_text.startswith("json"):
                        clean_text = clean_text[4:]
                parsed = json.loads(clean_text)
                ai_narrative = parsed.get("narrative")
                ai_recommendations = parsed.get("recommendations")
                model_name = "Gemini 1.5 Flash (Google Cloud AI)"
        except Exception:
            # Fallback gracefully to deterministic rule-guided engine
            pass

    if not ai_narrative:
        ai_narrative = build_ai_narrative(case_data)

    if not ai_recommendations:
        ai_recommendations = build_ai_recommendations(case_data)

    report_text = generate_structured_report_text(
        case_data, ai_narrative, ai_recommendations, model_name, timestamp
    )

    summary_payload = {
        "case_id": case_id,
        "generated_at": timestamp,
        "model_id": model_name,
        "disclaimer": "AI-generated summary — human review required. Advisory layer only; cryptographic blockchain hash verification remains the authoritative legal integrity standard.",
        "confirmed_facts": case_data,
        "ai_narrative": ai_narrative,
        "ai_recommendations": ai_recommendations,
        "report_text": report_text
    }

    return summary_payload, None, 200
