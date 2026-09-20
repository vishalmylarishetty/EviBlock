"""
ForensicChain v2.4.1 — Feature Engineering Pipeline
Extracts 12 numerical behavioral features from evidence records, custody timeline,
and access logs for unsupervised anomaly detection using Isolation Forest.
"""

from datetime import datetime, timezone
import dateutil.parser


FEATURE_NAMES = [
    "access_count",
    "failed_attempt_count",
    "transfer_count",
    "verification_failure_count",
    "unique_actor_count",
    "unique_role_count",
    "action_frequency",
    "min_time_between_actions",
    "unusual_hour_ratio",
    "repeated_action_burst",
    "unexpected_role_action",
    "custody_sequence_irregularity",
]


def parse_timestamp(val):
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return dateutil.parser.parse(str(val))
    except Exception:
        return None


def extract_evidence_features(evidence, custody_logs=None, access_entries=None):
    """
    Given an evidence dictionary and associated custody and access logs,
    extracts a 12-feature vector for the Isolation Forest model.
    
    Returns:
        feature_vector: list of 12 floats/ints in order of FEATURE_NAMES
        feature_dict: dict mapping feature name to value
        explanations: list of descriptive heuristic flags explaining anomalies
    """
    custody_logs = list(custody_logs or [])
    access_entries = list(access_entries or [])

    explanations = []

    # 1. access_count
    access_count = float(len(access_entries))

    # 2. failed_attempt_count (e.g. denied or unauthorized attempts)
    failed_attempt_count = 0.0
    for entry in access_entries:
        note = str(entry.get("note") or "").lower()
        src = str(entry.get("source") or "").lower()
        if "denied" in note or "unauthorized" in note or "failed" in note or "denied" in src:
            failed_attempt_count += 1.0

    # 3. transfer_count
    transfer_count = 0.0
    for cl in custody_logs:
        act = str(cl.get("action") or "").lower()
        if "transfer" in act or act == "transferred":
            transfer_count += 1.0

    # 4. verification_failure_count
    verification_failure_count = 0.0
    for cl in custody_logs:
        act = str(cl.get("action") or "").lower()
        note = str(cl.get("note") or "").lower()
        if "tamper" in act or "fail" in act or "failed" in note or "tamper" in note or "mismatch" in note:
            verification_failure_count += 1.0

    # 5. unique_actor_count
    actors = set()
    for cl in custody_logs:
        act = cl.get("actor") or cl.get("actor_name") or cl.get("user_id")
        if act:
            actors.add(str(act))
    for ae in access_entries:
        u = ae.get("user_id")
        if u:
            actors.add(str(u))
    unique_actor_count = float(len(actors)) if actors else 1.0

    # 6. unique_role_count
    roles = set()
    for cl in custody_logs:
        r = cl.get("actor_role")
        if r:
            roles.add(str(r).lower())
    unique_role_count = float(len(roles)) if roles else 1.0

    # Sort custody logs chronologically for sequence & timing features
    parsed_logs = []
    for cl in custody_logs:
        ts = parse_timestamp(cl.get("created_at") or cl.get("timestamp"))
        parsed_logs.append((ts, cl))
    parsed_logs.sort(key=lambda x: x[0] or datetime.min)

    # 7. action_frequency (actions per day)
    total_actions = len(custody_logs) + len(access_entries)
    created_ts = parse_timestamp(evidence.get("created_at")) if evidence else None
    now_ts = datetime.now()
    if created_ts:
        if created_ts.tzinfo is not None and now_ts.tzinfo is None:
            now_ts = datetime.now(timezone.utc)
        elapsed_hours = max(0.1, (now_ts - created_ts).total_seconds() / 3600.0)
        action_frequency = float(total_actions) / (elapsed_hours / 24.0)
    else:
        action_frequency = float(total_actions)

    # 8. min_time_between_actions (seconds)
    min_time_between = 86400.0
    if len(parsed_logs) >= 2:
        deltas = []
        for i in range(1, len(parsed_logs)):
            t_prev, _ = parsed_logs[i - 1]
            t_curr, _ = parsed_logs[i]
            if t_prev and t_curr:
                dt = abs((t_curr - t_prev).total_seconds())
                deltas.append(dt)
        if deltas:
            min_time_between = min(deltas)

    # 9. unusual_hour_ratio (fraction of actions between 23:00 and 05:00)
    unusual_hour_count = 0.0
    total_ts_count = 0.0
    for ts, _ in parsed_logs:
        if ts:
            total_ts_count += 1.0
            if ts.hour >= 23 or ts.hour < 5:
                unusual_hour_count += 1.0
    for ae in access_entries:
        ts = parse_timestamp(ae.get("created_at"))
        if ts:
            total_ts_count += 1.0
            if ts.hour >= 23 or ts.hour < 5:
                unusual_hour_count += 1.0
    unusual_hour_ratio = (unusual_hour_count / total_ts_count) if total_ts_count > 0 else 0.0

    # 10. repeated_action_burst (max consecutive repeats of same action by same user)
    max_burst = 1.0
    curr_burst = 1.0
    for i in range(1, len(custody_logs)):
        prev_act = custody_logs[i - 1].get("action")
        prev_user = custody_logs[i - 1].get("user_id")
        curr_act = custody_logs[i].get("action")
        curr_user = custody_logs[i].get("user_id")
        if prev_act == curr_act and prev_user == curr_user and prev_act is not None:
            curr_burst += 1.0
            if curr_burst > max_burst:
                max_burst = curr_burst
        else:
            curr_burst = 1.0
    repeated_action_burst = max_burst

    # 11. unexpected_role_action
    unexpected_role_action = 0.0
    # Expected roles for actions
    for cl in custody_logs:
        act = str(cl.get("action") or "").lower()
        role = str(cl.get("actor_role") or "").lower()
        # Mismatches:
        if "analysis" in act and role in {"police", "witness"}:
            unexpected_role_action += 1.0
        elif "seal" in act and role not in {"court_authority", "admin"}:
            unexpected_role_action += 1.0
        elif "attest" in act and role not in {"witness", "admin"}:
            # some relaxed rule
            pass

    # 12. custody_sequence_irregularity
    # Standard lifecycle progression:
    # 1: Upload / Seizure -> 2: Attest -> 3: Collect -> 4: Transfer -> 5/6: Analysis -> 7: Verify -> 8: Court -> 9: Stored/Sealed
    sequence_stage_order = {
        "evidence uploaded / seizure initiated": 1,
        "witness attested": 2,
        "evidence collected": 3,
        "collected": 3,
        "evidence transferred": 4,
        "transferred": 4,
        "forensic analysis started": 5,
        "forensic analysis completed": 6,
        "analyzed": 6,
        "evidence verified": 7,
        "verified": 7,
        "evidence presented to court": 8,
        "presented": 8,
        "evidence stored": 9,
        "evidence released": 9,
        "evidence destroyed": 9,
        "sealed by court": 9,
        "stored": 9,
    }

    sequence_irregularity = 0.0
    last_stage_seen = 0
    for ts, cl in parsed_logs:
        act = str(cl.get("action") or "").lower()
        stage = sequence_stage_order.get(act, 0)
        if stage > 0:
            # If skipping backwards drastically or analyzing before collection
            if stage < last_stage_seen and (last_stage_seen - stage) >= 2:
                # Big retrograde jump (e.g. presented to court, then collection)
                sequence_irregularity += 1.0
            if stage in {5, 6} and last_stage_seen < 3 and len(parsed_logs) > 1:
                # Analysis before collection
                sequence_irregularity += 1.0
            last_stage_seen = max(last_stage_seen, stage)

    # Compile human-readable explanations based on high-risk feature indicators
    if verification_failure_count > 0:
        explanations.append(f"Recorded {int(verification_failure_count)} cryptographic verification failure(s) or tampering alert(s).")
    if failed_attempt_count > 0:
        explanations.append(f"Detected {int(failed_attempt_count)} unauthorized access or permission denial event(s).")
    if unusual_hour_ratio > 0.4:
        explanations.append(f"High ratio ({int(unusual_hour_ratio * 100)}%) of actions conducted during non-business night hours (23:00-05:00).")
    if min_time_between < 5.0 and len(parsed_logs) >= 2:
        explanations.append(f"Rapid automated burst detected ({int(min_time_between)}s elapsed between sequential custody operations).")
    if repeated_action_burst >= 4:
        explanations.append(f"Excessive repeated action burst ({int(repeated_action_burst)} consecutive identical actions by same actor).")
    if unexpected_role_action > 0:
        explanations.append(f"Encountered {int(unexpected_role_action)} action(s) executed by atypical or non-authorized organizational roles.")
    if sequence_irregularity > 0:
        explanations.append("Custody progression contains out-of-order sequence transitions (e.g. analysis prior to seizure collection).")
    if action_frequency > 50.0:
        explanations.append(f"Unusually high activity frequency ({action_frequency:.1f} actions/day).")

    if not explanations:
        explanations.append("Custody, verification, and access history follow expected operational patterns.")

    feature_dict = {
        "access_count": access_count,
        "failed_attempt_count": failed_attempt_count,
        "transfer_count": transfer_count,
        "verification_failure_count": verification_failure_count,
        "unique_actor_count": unique_actor_count,
        "unique_role_count": unique_role_count,
        "action_frequency": round(action_frequency, 2),
        "min_time_between_actions": round(min_time_between, 2),
        "unusual_hour_ratio": round(unusual_hour_ratio, 3),
        "repeated_action_burst": repeated_action_burst,
        "unexpected_role_action": unexpected_role_action,
        "custody_sequence_irregularity": sequence_irregularity,
    }

    feature_vector = [feature_dict[name] for name in FEATURE_NAMES]
    return feature_vector, feature_dict, explanations
