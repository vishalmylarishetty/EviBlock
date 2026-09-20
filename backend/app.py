import hashlib
import hmac
import mimetypes
import os
import shutil
import secrets
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
import importlib

import jwt
from flask import Flask, jsonify, request, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

if __package__:
    from . import database as db
    from .blockchain import blockchain
else:
    import database as db
    from blockchain import blockchain

# ── ML Anomaly Detection Engine (Graceful fallback) ─────────────────────────
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from ml.feature_engineering import extract_evidence_features
    from ml.anomaly_detector import AnomalyDetector
    ml_detector = AnomalyDetector.get_instance()
except Exception as _ml_import_err:
    print(f"[ML Init Warning] {str(_ml_import_err)}")
    ml_detector = None
    extract_evidence_features = None



FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
ERR_INVALID_REQUEST_BODY = "Invalid request body"
ERR_USER_NOT_FOUND = "User not found"
ERR_EVIDENCE_NOT_FOUND = "Evidence not found"
ERR_EVIDENCE_ID_REQUIRED = "evidence_id required"
BCRYPT_AVAILABLE = importlib.util.find_spec("bcrypt") is not None


def now_utc():
    return datetime.now(timezone.utc)


APP_STARTED_AT = now_utc()


# App setup
app = Flask(__name__, static_folder=FRONTEND_DIR, template_folder=FRONTEND_DIR)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

MAX_EVIDENCE_FILE_SIZE_MB = int(os.environ.get("MAX_EVIDENCE_FILE_SIZE_MB", 25))
MAX_EVIDENCE_FILE_SIZE_BYTES = MAX_EVIDENCE_FILE_SIZE_MB * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_EVIDENCE_FILE_SIZE_BYTES

CORS(app, supports_credentials=True)


# Email configuration
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "noreply@forensicchain.com")
APP_URL = os.environ.get("APP_URL", "http://localhost:5000")
EMAILS_ENABLED = bool(SMTP_USERNAME and SMTP_PASSWORD)


# JWT configuration
JWT_SECRET = os.environ.get("JWT_SECRET", app.secret_key)
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", 8))


# Upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "evidence_storage")
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "pcap", "log",
    "zip", "tar", "gz", "img", "dd", "e01", "csv", "json", "xml", "eml", "reg"
}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg"}
PDF_EXTENSIONS = {"pdf"}
TEXT_EXTENSIONS = {"txt", "log", "csv", "json", "xml", "eml", "reg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Init services
REQUIRE_DB = os.environ.get("REQUIRE_DB", "true").lower() == "true"

try:
    db.init_db()
except Exception:
    app.logger.exception("Database initialization failed. Check DATABASE_URL and PostgreSQL availability.")
    if REQUIRE_DB:
        raise

try:
    blockchain.connect()
except Exception:
    app.logger.exception("Blockchain initialization failed. App will continue in degraded mode.")


# Helpers

def send_email(recipient_email, subject, html_body):
    if not EMAILS_ENABLED:
        app.logger.warning("Email disabled. Would send to %s: %s", recipient_email, subject)
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = recipient_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())

        return True
    except Exception as exc:
        app.logger.error("Failed to send email: %s", str(exc))
        return False


def send_login_notification(user_email, user_name):
    subject = "ForensicChain - Login Notification"
    html_body = f"""
    <html>
        <body>
            <h2>Login Alert</h2>
            <p>Hi {user_name},</p>
            <p>Your account was logged in at <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong>.</p>
            <p>If this wasn't you, please reset your password immediately.</p>
            <p>Best regards,<br>ForensicChain Team</p>
        </body>
    </html>
    """
    return send_email(user_email, subject, html_body)


def send_password_reset_email(user_email, reset_token):
    reset_link = f"{APP_URL}/reset-password.html?token={reset_token}&email={user_email}"
    subject = "ForensicChain - Password Reset Request"
    html_body = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password.</p>
            <p><a href=\"{reset_link}\" style=\"background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;\">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, you can ignore this email.</p>
            <p>Best regards,<br>ForensicChain Team</p>
        </body>
    </html>
    """
    return send_email(user_email, subject, html_body)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_extension(filename):
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def infer_preview_kind(filename):
    ext = get_extension(filename)
    if ext in IMAGE_EXTENSIONS:
        return "image"
    if ext in PDF_EXTENSIONS:
        return "pdf"
    if ext in TEXT_EXTENSIONS:
        return "text"
    return "none"


def can_preview(filename):
    return infer_preview_kind(filename) != "none"


def candidate_storage_names(evidence):
    candidates = []
    raw_name = (evidence.get("file_path") or "").strip()
    if raw_name:
        candidates.extend([raw_name, os.path.basename(raw_name)])

    original_name = (evidence.get("file_name") or "").strip()
    if original_name:
        candidates.append(original_name)
    return candidates, original_name


def find_existing_storage_file(candidates):
    seen = set()
    for name in candidates:
        normalized = (name or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)

        abs_path = os.path.join(UPLOAD_FOLDER, normalized)
        if os.path.exists(abs_path):
            return normalized, abs_path
    return None, None


def find_storage_file_by_suffix(original_name):
    if not original_name or not os.path.isdir(UPLOAD_FOLDER):
        return None, None

    lowered_original = original_name.lower()
    for entry in os.listdir(UPLOAD_FOLDER):
        entry_l = entry.lower()
        if entry_l == lowered_original or entry_l.endswith("_" + lowered_original):
            abs_path = os.path.join(UPLOAD_FOLDER, entry)
            if os.path.exists(abs_path):
                return entry, abs_path
    return None, None


def resolve_storage_file(evidence):
    """Resolve file path from DB to an existing file in storage.

    Returns tuple: (storage_name, absolute_path). When not found, returns (None, None).
    """
    candidates, original_name = candidate_storage_names(evidence)
    storage_name, abs_path = find_existing_storage_file(candidates)
    if abs_path:
        return storage_name, abs_path
    return find_storage_file_by_suffix(original_name)


def extract_upload_form_fields():
    return {
        "case_id": request.form.get("case_id", "").strip(),
        "warrant_number": request.form.get("warrant_number", "").strip(),
        "source_gps": request.form.get("source_gps", "").strip(),
        "source_device_id": request.form.get("source_device_id", "").strip(),
        "witness_user_id": request.form.get("witness_user_id", "").strip(),
        "is_private": parse_bool(request.form.get("is_private"), default=False),
        "description": request.form.get("description", ""),
    }


def validate_seizure_form_fields(form_fields):
    validations = {
        "case_id": "case_id is required for legal seizure protocol",
        "warrant_number": "warrant_number is required for legal seizure protocol",
        "source_gps": "source_gps is required for legal seizure protocol",
        "source_device_id": "source_device_id is required for legal seizure protocol",
        "witness_user_id": "witness_user_id is required for two-factor seizure",
    }
    for field, message in validations.items():
        if not form_fields.get(field):
            return jsonify({"error": message}), 400
    return None


def load_witness_or_error(witness_user_id, uploader_id):
    try:
        witness_user_id_int = int(witness_user_id)
    except ValueError:
        return None, None, (jsonify({"error": "witness_user_id must be a valid user id"}), 400)

    witness = db.get_user_by_id(witness_user_id_int)
    if not witness or not witness.get("is_active", True):
        return None, None, (jsonify({"error": "Selected witness is invalid or inactive"}), 400)
    if witness["id"] == uploader_id:
        return None, None, (jsonify({"error": "Witness must be a different user"}), 400)
    return witness_user_id_int, witness, None


def resolve_verify_input_or_error():
    if "file" in request.files:
        file = request.files["file"]
        evidence_id = request.form.get("evidence_id")
        if not evidence_id:
            return None, None, (jsonify({"error": ERR_EVIDENCE_ID_REQUIRED}), 400)
        return evidence_id, generate_hash_from_bytes(file.read()), None

    body = request.get_json()
    if not body:
        return None, None, (jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400)

    evidence_id = body.get("evidence_id")
    if not evidence_id:
        return None, None, (jsonify({"error": ERR_EVIDENCE_ID_REQUIRED}), 400)

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return None, None, (jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404)

    storage_name, file_path = resolve_storage_file(evidence)
    if not file_path:
        return None, None, (jsonify({"error": "Evidence file missing from storage"}), 404)

    if storage_name != (evidence.get("file_path") or ""):
        db.update_evidence_file_path(evidence_id, storage_name)

    return evidence_id, generate_file_hash(file_path), None


def db_fallback_verify_result(evidence_id, current_hash):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return None, (jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404)
    stored_hash = evidence["file_hash"]
    return {
        "intact": stored_hash.lower() == current_hash.lower(),
        "stored_hash": stored_hash,
        "current_hash": current_hash,
        "evidence_id": evidence_id,
        "source": "database",
    }, None


def append_system_timeline_events(timeline, system_logs, evidence_created_at):
    evidence_day = evidence_created_at.date() if evidence_created_at else None
    for entry in system_logs:
        ts = entry.get("created_at")
        if evidence_day and ts and ts.date() != evidence_day:
            continue
        timeline.append(
            {
                "type": "system",
                "label": entry.get("event_type") or "SYSTEM_EVENT",
                "message": entry.get("message") or "System event",
                "timestamp": ts,
            }
        )


def append_evidence_timeline_events(timeline, evidence_logs):
    for entry in evidence_logs:
        timeline.append(
            {
                "type": "evidence",
                "label": entry.get("action") or "Evidence Action",
                "message": entry.get("note") or "",
                "timestamp": entry.get("created_at"),
                "tx_hash": entry.get("tx_hash"),
                "actor_name": entry.get("actor_name"),
            }
        )


def append_blockchain_timeline_item(timeline, label, tx_meta, fallback_ts):
    if not tx_meta:
        return
    timestamp = datetime.fromtimestamp(tx_meta["timestamp"]) if tx_meta.get("timestamp") else fallback_ts
    timeline.append(
        {
            "type": "blockchain",
            "label": label,
            "message": f"Status={tx_meta.get('status')} Block={tx_meta.get('block_number')}",
            "timestamp": timestamp,
            "tx_hash": tx_meta.get("tx_hash"),
        }
    )


def iter_unique_custody_tx_hashes(evidence_logs, seen_txs):
    for entry in evidence_logs:
        tx_hash = entry.get("tx_hash")
        if not tx_hash or tx_hash in seen_txs:
            continue
        seen_txs.add(tx_hash)
        yield entry, tx_hash


def append_blockchain_timeline_events(timeline, evidence, evidence_logs):
    seen_txs = set()
    if evidence.get("tx_hash"):
        initial_hash = evidence["tx_hash"]
        seen_txs.add(initial_hash)
        tx_meta, _ = blockchain.get_transaction_info(initial_hash)
        append_blockchain_timeline_item(timeline, "Initial Registration", tx_meta, evidence.get("created_at"))

    for entry, tx_hash in iter_unique_custody_tx_hashes(evidence_logs, seen_txs):
        tx_meta, _ = blockchain.get_transaction_info(tx_hash)
        label = f"Blockchain: {entry.get('action') or 'Event'}"
        append_blockchain_timeline_item(timeline, label, tx_meta, entry.get("created_at"))


def generate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_hash_from_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_symbol


def hash_password(password: str) -> str:
    if BCRYPT_AVAILABLE:
        bcrypt = importlib.import_module("bcrypt")
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")
    return generate_password_hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    if BCRYPT_AVAILABLE:
        bcrypt = importlib.import_module("bcrypt")
        if hashed_password.startswith("$2"):
            return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    return check_password_hash(hashed_password, password)


def generate_jwt_token(user_id, role):
    try:
        issued_at = now_utc()
        payload = {
            "user_id": user_id,
            "role": role,
            "iat": issued_at,
            "exp": issued_at + timedelta(hours=JWT_EXPIRATION_HOURS),
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    except Exception as exc:
        app.logger.error("JWT generation failed: %s", str(exc))
        return None


def verify_jwt_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_jwt_from_request():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.cookies.get("access_token")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)

    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "Authentication required"}), 401
            user = db.get_user_by_id(session["user_id"])
            if not user or user["role"] not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)

        return decorated

    return decorator


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_jwt_from_request()
        if not token:
            return jsonify({"error": "Missing authentication token"}), 401

        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        request.user_id = payload.get("user_id")
        request.user_role = payload.get("role")
        return f(*args, **kwargs)

    return decorated


def jwt_role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = get_jwt_from_request()
            if not token:
                return jsonify({"error": "Missing authentication token"}), 401

            payload = verify_jwt_token(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401

            user_role = payload.get("role")
            if user_role not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403

            request.user_id = payload.get("user_id")
            request.user_role = user_role
            return f(*args, **kwargs)

        return decorated

    return decorator


def build_preview_metadata(evidence_id, file_name, storage_name=None):
    kind = infer_preview_kind(file_name)
    storage_available = True
    if storage_name is not None:
        normalized_storage = str(storage_name).strip()
        storage_available = bool(normalized_storage) and os.path.exists(
            os.path.join(UPLOAD_FOLDER, normalized_storage)
        )

    preview_supported = kind != "none" and storage_available
    return {
        "supported": preview_supported,
        "kind": kind,
        "storage_available": storage_available,
        "url": f"/api/evidence/{evidence_id}/file" if preview_supported else None,
    }


def offline_tx_meta():
    return {
        "tx_hash": "OFFLINE-" + uuid.uuid4().hex[:16],
        "block_number": None,
        "timestamp": None,
        "status": "offline",
        "source": "fallback",
    }


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def user_can_access_evidence(user, evidence):
    if user["role"] in {"admin", "court_authority"}:
        return True

    # Designated witness can always access to inspect and attest
    if int(evidence.get("witness_required_id") or 0) == int(user["id"]):
        return True

    # Witness who previously signed can access
    if int(evidence.get("witness_signed_by") or 0) == int(user["id"]):
        return True

    # Original uploader can always access
    if int(evidence.get("uploaded_by") or 0) == int(user["id"]):
        return True

    # For witness role, do not leak other general evidence
    if user["role"] == "witness":
        return False

    # Public (non-private) evidence is accessible by all authenticated investigators/police/analysts
    if not evidence.get("is_private"):
        return True

    if user["role"] == "police":
        return db.has_police_access_grant(evidence["evidence_id"], user["id"])

    if user["role"] in {"investigator", "analyst"}:
        return db.has_approved_access(evidence["evidence_id"], user["id"])

    return False


def evidence_is_sealed(evidence):
    return bool(evidence and evidence.get("is_sealed"))


def get_system_health_snapshot():
    stats = db.get_stats()

    conn = None
    db_connected = False
    db_error = None
    try:
        conn = db.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_connected = True
    except Exception as exc:
        db_error = str(exc)
    finally:
        if conn is not None:
            conn.close()

    total_storage_bytes = 0
    if os.path.isdir(UPLOAD_FOLDER):
        for root, _, files in os.walk(UPLOAD_FOLDER):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    total_storage_bytes += os.path.getsize(file_path)
                except OSError:
                    continue

    disk_info = shutil.disk_usage(UPLOAD_FOLDER)
    uptime_seconds = int((now_utc() - APP_STARTED_AT).total_seconds())

    return {
        "status": "healthy" if db_connected else "degraded",
        "uptime_seconds": uptime_seconds,
        "database": {
            "connected": db_connected,
            "error": db_error,
        },
        "blockchain": {
            "connected": bool(blockchain.is_connected),
            "contract_address": blockchain.contract_address,
        },
        "users": {
            "total": stats.get("total_users", 0),
            "active": stats.get("active_users", 0),
            "disabled": stats.get("disabled_users", 0),
        },
        "evidence": {
            "total": stats.get("total_evidence", 0),
            "verified": stats.get("verified", 0),
            "tampered": stats.get("tampered", 0),
        },
        "storage": {
            "evidence_bytes": total_storage_bytes,
            "disk_total_bytes": disk_info.total,
            "disk_free_bytes": disk_info.free,
        },
    }


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(
        {
            "error": f"File too large. Max allowed size is {MAX_EVIDENCE_FILE_SIZE_MB} MB",
            "max_size_mb": MAX_EVIDENCE_FILE_SIZE_MB,
        }
    ), 413


# Frontend routes
@app.route("/", methods=["GET"])
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


SAMPLE_EVIDENCES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_evidences"))


@app.route("/api/sample-evidences", methods=["GET"])
def get_sample_evidences_list():
    """List all available pre-packaged sample forensic evidence files."""
    if not os.path.exists(SAMPLE_EVIDENCES_DIR):
        return jsonify({"files": []}), 200
    files = []
    for fname in sorted(os.listdir(SAMPLE_EVIDENCES_DIR)):
        fpath = os.path.join(SAMPLE_EVIDENCES_DIR, fname)
        if os.path.isfile(fpath):
            files.append({
                "filename": fname,
                "size": os.path.getsize(fpath),
                "url": f"/api/sample-evidences/{fname}"
            })
    return jsonify({"files": files}), 200


@app.route("/api/sample-evidences/<path:filename>", methods=["GET"])
def download_sample_evidence(filename):
    """Download or fetch raw sample evidence file."""
    return send_from_directory(SAMPLE_EVIDENCES_DIR, filename, as_attachment=False)


@app.route("/<path:filename>", methods=["GET"])
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


@app.route("/health", methods=["GET"])
def health():
    db_ok = False
    db_error = None

    conn = None
    try:
        conn = db.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_ok = True
    except Exception as exc:
        db_error = str(exc)
    finally:
        if conn is not None:
            conn.close()

    payload = {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else "error",
        "blockchain_connected": bool(blockchain.is_connected),
    }
    if db_error:
        payload["database_error"] = db_error

    return jsonify(payload), 200 if db_ok else 503


@app.route("/status", methods=["GET"])
def status():
    return jsonify(
        {
            "connected": bool(blockchain.w3 and blockchain.w3.is_connected()),
            "network": "sepolia",
        }
    ), 200


# Auth API
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    required = ["name", "email", "password", "password_confirm", "role"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing required fields"}), 400

    valid_roles = ["investigator", "police", "analyst", "court_authority", "witness"]
    if data["role"] == "admin":
        return jsonify({"error": "Admin registration is disabled. Configure one private admin via environment variables."}), 403
    if data["role"] not in valid_roles:
        return jsonify({"error": "Invalid role"}), 400

    if data["password"] != data["password_confirm"]:
        return jsonify({"error": "Passwords do not match"}), 400

    if not is_strong_password(data["password"]):
        return jsonify({"error": "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol"}), 400

    hashed = hash_password(data["password"])
    success = db.create_user(
        data["name"], data["email"], hashed, data["role"], data.get("wallet_address", "")
    )
    if not success:
        return jsonify({"error": "Email already registered"}), 409

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/api/users/witness-candidates", methods=["GET"])
@login_required
def witness_candidates():
    users = db.get_user_witness_candidates(exclude_user_id=session["user_id"])
    return jsonify(users)


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Email and password required"}), 400

    user = db.get_user_by_email(data["email"])
    if not user or not verify_password(data["password"], user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.get("is_active", True):
        return jsonify({"error": "Account disabled. Contact administrator."}), 403

    session.permanent = True
    session["user_id"] = user["id"]
    session["role"] = user["role"]

    db.update_last_login(user["id"])
    db.add_system_log(
        user["id"],
        "USER_LOGIN",
        f"User logged in: {user['email']}",
        f"role={user['role']}",
    )
    send_login_notification(user["email"], user["name"])

    jwt_token = generate_jwt_token(user["id"], user["role"])
    if not jwt_token:
        return jsonify({"error": "Failed to generate authentication token"}), 500

    return jsonify(
        {
            "message": "Login successful",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "wallet_address": user["wallet_address"],
            },
            "token": jwt_token,
            "token_type": "Bearer",
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
        }
    )


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    if "user_id" in session:
        try:
            db.add_system_log(session["user_id"], "USER_LOGOUT", "User logged out", "")
        except Exception:
            app.logger.exception("Failed to persist logout system log")
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Email required"}), 400

    email = data["email"]
    user = db.get_user_by_email(email)

    if not user:
        return jsonify({"message": "If this email exists, a reset link has been sent"}), 200

    reset_token = secrets.token_urlsafe(32)
    if not db.set_password_reset_token(email, reset_token):
        return jsonify({"error": "Failed to initiate password reset"}), 500

    send_password_reset_email(email, reset_token)
    return jsonify({"message": "If this email exists, a reset link has been sent"}), 200


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password_confirm():
    data = request.get_json()
    if not data or "email" not in data or "token" not in data or "password" not in data:
        return jsonify({"error": "Email, token, and password required"}), 400

    email = data["email"]
    token = data["token"]
    password = data["password"]

    if not db.verify_reset_token(email, token):
        return jsonify({"error": "Invalid or expired reset token"}), 401

    if not is_strong_password(password):
        return jsonify({"error": "Password must be at least 12 characters and include uppercase, lowercase, number, and symbol"}), 400

    hashed = hash_password(password)
    if not db.reset_password(email, hashed):
        return jsonify({"error": "Failed to reset password"}), 500

    return jsonify({"message": "Password reset successful"}), 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def me():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    return jsonify(
        {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "wallet_address": user["wallet_address"],
        }
    )


@app.route("/api/auth/validate-token", methods=["POST"])
@jwt_required
def validate_token():
    user = db.get_user_by_id(request.user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    return jsonify(
        {
            "valid": True,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
            },
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
        }
    )


@app.route("/api/auth/refresh-token", methods=["POST"])
@jwt_required
def refresh_token():
    new_token = generate_jwt_token(request.user_id, request.user_role)
    if not new_token:
        return jsonify({"error": "Failed to generate new token"}), 500

    return jsonify(
        {
            "token": new_token,
            "token_type": "Bearer",
            "expires_in": JWT_EXPIRATION_HOURS * 3600,
        }
    )


# Evidence API
@app.route("/api/upload_evidence", methods=["POST"])
@role_required("investigator", "police", "admin")
def upload_evidence():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    if user["role"] not in ["investigator", "police", "admin"]:
        return jsonify({"error": "Only police/investigator/admin roles can initiate legal seizure uploads"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    original_filename = secure_filename(file.filename)
    if not original_filename:
        return jsonify({"error": "Invalid filename"}), 400

    file_bytes = file.read()
    file_size = len(file_bytes)
    if file_size > MAX_EVIDENCE_FILE_SIZE_BYTES:
        return jsonify({"error": f"File too large. Max allowed size is {MAX_EVIDENCE_FILE_SIZE_MB} MB"}), 413

    file_hash = generate_hash_from_bytes(file_bytes)
    duplicate = db.get_evidence_by_hash(file_hash)
    if duplicate:
        return jsonify(
            {
                "error": "Duplicate evidence detected",
                "duplicate_evidence": {
                    "evidence_id": duplicate["evidence_id"],
                    "file_name": duplicate["file_name"],
                    "uploaded_at": duplicate["created_at"],
                    "case_id": duplicate.get("case_id"),
                },
            }
        ), 409

    form_fields = extract_upload_form_fields()
    form_error = validate_seizure_form_fields(form_fields)
    if form_error:
        return form_error

    witness_user_id_int, witness, witness_error = load_witness_or_error(
        form_fields["witness_user_id"],
        user["id"],
    )
    if witness_error:
        return witness_error

    evidence_id = "EV-" + uuid.uuid4().hex[:8].upper()
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
    stored_filename = timestamp_prefix + original_filename
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)

    with open(file_path, "wb") as out:
        out.write(file_bytes)

    # Anchor evidence registration on blockchain immediately
    tx_meta, bc_err = blockchain.add_evidence(
        evidence_id,
        file_hash,
        original_filename,
        form_fields["case_id"] or "CASE-UNKNOWN",
    )
    if bc_err:
        app.logger.warning("Upload evidence blockchain registration fallback: %s", bc_err)
        tx_meta = offline_tx_meta()

    tx_hash = tx_meta["tx_hash"]

    db.save_evidence(
        evidence_id,
        original_filename,
        stored_filename,
        file_size,
        file_hash,
        form_fields["case_id"],
        form_fields["description"],
        session["user_id"],
        tx_hash,
        warrant_number=form_fields["warrant_number"],
        source_gps=form_fields["source_gps"],
        source_device_id=form_fields["source_device_id"],
        is_private=form_fields["is_private"],
        witness_required_id=witness_user_id_int,
    )

    db.add_custody_log(
        evidence_id,
        "Evidence Uploaded / Seizure Initiated",
        session["user_id"],
        f"Seizure initiated under warrant {form_fields['warrant_number']}. Awaiting witness signature.",
        tx_hash,
    )

    return jsonify(
        {
            "message": "Seizure initiated. Awaiting witness attestation.",
            "evidence_id": evidence_id,
            "file_hash": file_hash,
            "tx_hash": tx_hash,
            "status": "pending_witness",
            "witness_required_id": witness_user_id_int,
            "witness_required_name": witness["name"],
            "seizure_metadata": {
                "case_id": form_fields["case_id"],
                "warrant_number": form_fields["warrant_number"],
                "source_gps": form_fields["source_gps"],
                "source_device_id": form_fields["source_device_id"],
                "is_private": form_fields["is_private"],
            },
            "preview": build_preview_metadata(evidence_id, original_filename),
            "max_size_mb": MAX_EVIDENCE_FILE_SIZE_MB,
        }
    ), 202


@app.route("/api/seizure/attest", methods=["POST"])
@role_required("witness", "investigator", "police", "admin")
def attest_seizure():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    evidence_id = data.get("evidence_id", "").strip()
    note = data.get("note", "").strip()
    if not evidence_id:
        return jsonify({"error": ERR_EVIDENCE_ID_REQUIRED}), 400

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    status = str(evidence.get("status") or "").strip().lower()
    tx_hash = str(evidence.get("tx_hash") or "")
    legacy_pending = (
        status == "active"
        and evidence.get("witness_required_id")
        and not evidence.get("witness_signed_by")
        and tx_hash.startswith("PENDING-WITNESS-")
    )

    if status != "pending_witness" and not legacy_pending:
        return jsonify({"error": "Evidence is not awaiting witness attestation"}), 409
    if session.get("role") != "admin" and int(evidence.get("witness_required_id") or 0) != int(session["user_id"]):
        return jsonify({"error": "Only the designated witness can attest this seizure"}), 403

    # Backward compatibility for records created before pending_witness status was persisted.
    if legacy_pending:
        db.update_evidence_status(evidence_id, "pending_witness")

    # Register on blockchain if not already registered (e.g. legacy records or previous offline fallback)
    exists, _ = blockchain.evidence_exists(evidence_id)
    if not exists:
        tx_meta, bc_err = blockchain.add_evidence(
            evidence_id,
            evidence["file_hash"],
            evidence["file_name"],
            evidence.get("case_id") or "CASE-UNKNOWN",
        )
        if bc_err:
            app.logger.warning("Witness attestation blockchain registration failed: %s", bc_err)
            tx_meta = offline_tx_meta()
        tx_hash = tx_meta["tx_hash"]
    else:
        tx_hash = evidence.get("tx_hash") or ""
        tx_meta, _ = blockchain.get_transaction_info(tx_hash)
        if not tx_meta:
            tx_meta = {"tx_hash": tx_hash, "status": "confirmed"}
        bc_err = None

    db.mark_evidence_witness_signed(evidence_id, session["user_id"], tx_hash)

    user = db.get_user_by_id(session["user_id"]) or {}
    actor_name = user.get("name", "Witness")
    actor_role = user.get("role", "witness")

    tx_meta_transfer, bc_err_transfer = blockchain.record_custody_action(
        evidence_id,
        "Witness Attested",
        actor_name=actor_name,
        actor_role=actor_role,
        note=note or "Witness attested seizure handshake",
        case_id=evidence.get("case_id") or "",
    )
    if bc_err_transfer:
        tx_meta_transfer = offline_tx_meta()

    db.add_custody_log(
        evidence_id,
        "Witness Attested",
        session["user_id"],
        note or "Two-factor seizure handshake completed",
        tx_meta_transfer["tx_hash"],
    )

    return jsonify(
        {
            "message": "Witness attestation completed. Evidence is now on-chain.",
            "evidence_id": evidence_id,
            "tx_hash": tx_hash,
            "tx_metadata": tx_meta,
            "attestation_tx_metadata": tx_meta_transfer,
            "blockchain_registered": bc_err is None,
            "blockchain_error": bc_err,
        }
    )


@app.route("/api/evidence/<evidence_id>/update", methods=["POST"])
@role_required("investigator", "police")
def update_evidence(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
        
    user = db.get_user_by_id(session["user_id"])
    if int(evidence.get("uploaded_by") or 0) != int(user["id"]) and user["role"] != "admin":
        return jsonify({"error": "Only the original uploader can modify this evidence"}), 403
        
    if evidence_is_sealed(evidence):
        return jsonify({"error": "Evidence is court-sealed and cannot be modified"}), 423

    description = (request.form.get("description") or (request.json.get("description") if request.is_json else "") or "").strip()
    witness_id = request.form.get("witness_user_id") or (request.json.get("witness_user_id") if request.is_json else None)

    file_name = None
    file_path = None
    file_hash = None
    file_size = None

    if "file" in request.files and request.files["file"].filename:
        file = request.files["file"]
        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400
        original_filename = secure_filename(file.filename)
        file_bytes = file.read()
        file_size = len(file_bytes)
        if file_size > MAX_EVIDENCE_FILE_SIZE_BYTES:
            return jsonify({"error": f"File too large. Max allowed size is {MAX_EVIDENCE_FILE_SIZE_MB} MB"}), 413
            
        file_hash = generate_hash_from_bytes(file_bytes)
        timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
        stored_filename = timestamp_prefix + original_filename
        abs_path = os.path.join(UPLOAD_FOLDER, stored_filename)
        with open(abs_path, "wb") as out:
            out.write(file_bytes)
        file_name = original_filename
        file_path = stored_filename

    db.update_evidence_details(
        evidence_id,
        description=description if description else None,
        file_name=file_name,
        file_path=file_path,
        file_hash=file_hash,
        file_size=file_size,
        witness_required_id=int(witness_id) if witness_id else None
    )

    db.add_custody_log(
        evidence_id,
        "Evidence Modified by Uploader",
        session["user_id"],
        "Uploader updated evidence details/file. Status reset to pending witness approval.",
    )

    return jsonify({
        "message": f"Evidence '{evidence_id}' updated! Status reset to pending witness approval.",
        "evidence_id": evidence_id,
        "status": "pending_witness"
    })


@app.route("/api/evidence", methods=["GET"])
@login_required
def list_evidence():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    if user["role"] in {"admin", "court_authority"}:
        evidence_list = db.get_all_evidence()
    else:
        all_items = db.get_all_evidence()
        evidence_list = [e for e in all_items if user_can_access_evidence(user, e)]

    enriched = []
    for item in evidence_list:
        row = dict(item)
        row["preview"] = build_preview_metadata(row["evidence_id"], row["file_name"], row.get("file_path"))
        enriched.append(row)
    return jsonify(enriched)


@app.route("/api/witness/pending", methods=["GET"])
@role_required("witness", "admin", "investigator", "police")
def witness_pending():
    """Retrieve evidence waiting for attestation by the currently logged-in user."""
    user_id = session.get("user_id")
    items = db.get_pending_witness_evidence(user_id)
    enriched = []
    for item in items:
        row = dict(item)
        row["preview"] = build_preview_metadata(row["evidence_id"], row["file_name"], row.get("file_path"))
        enriched.append(row)
    return jsonify(enriched)


@app.route("/api/witness/attestations", methods=["GET"])
@role_required("witness", "admin", "investigator", "police")
def witness_signed_attestations():
    """Retrieve historical evidence attested by the currently logged-in user."""
    user_id = session.get("user_id")
    items = db.get_witness_attestations(user_id)
    enriched = []
    for item in items:
        row = dict(item)
        row["preview"] = build_preview_metadata(row["evidence_id"], row["file_name"], row.get("file_path"))
        enriched.append(row)
    return jsonify(enriched)


def build_lifecycle_stages(evidence, custody_logs=None):
    """
    Computes status and blockchain confirmation for the 9 evidence lifecycle stages:
    1. Evidence Uploaded / Seizure Initiated
    2. Witness Attested
    3. Evidence Collected
    4. Evidence Transferred
    5. Forensic Analysis Started
    6. Forensic Analysis Completed
    7. Evidence Verified
    8. Evidence Presented to Court
    9. Evidence Stored / Released / Destroyed
    """
    if custody_logs is None:
        custody_logs = db.get_custody_logs(evidence["evidence_id"])

    def resolve_bc_status(tx_hash):
        if not tx_hash:
            return "Pending"
        tx_str = str(tx_hash).strip()
        if tx_str.startswith("PENDING-"):
            return "Pending"
        if tx_str.startswith("OFFLINE-"):
            return "Database/Fallback"
        if tx_str.startswith("0x") or len(tx_str) >= 40:
            return "Blockchain Confirmed"
        return "Database/Fallback"

    stage_defs = [
        {
            "stage": 1,
            "key": "uploaded",
            "name": "Evidence Uploaded / Seizure Initiated",
            "actions": ["evidence uploaded / seizure initiated", "seizure initiated", "uploaded", "collected"],
        },
        {
            "stage": 2,
            "key": "witness_attested",
            "name": "Witness Attested",
            "actions": ["witness attested", "attested"],
        },
        {
            "stage": 3,
            "key": "collected",
            "name": "Evidence Collected",
            "actions": ["evidence collected", "collected"],
        },
        {
            "stage": 4,
            "key": "transferred",
            "name": "Evidence Transferred",
            "actions": ["evidence transferred", "transferred"],
        },
        {
            "stage": 5,
            "key": "analysis_started",
            "name": "Forensic Analysis Started",
            "actions": ["forensic analysis started", "analysis started"],
        },
        {
            "stage": 6,
            "key": "analysis_completed",
            "name": "Forensic Analysis Completed",
            "actions": ["forensic analysis completed", "analyzed", "analysis completed", "derived evidence created", "derived"],
        },
        {
            "stage": 7,
            "key": "verified",
            "name": "Evidence Verified",
            "actions": ["evidence verified", "verified"],
        },
        {
            "stage": 8,
            "key": "presented",
            "name": "Evidence Presented to Court",
            "actions": ["evidence presented to court", "presented", "court review"],
        },
        {
            "stage": 9,
            "key": "final_disposition",
            "name": "Evidence Stored / Released / Destroyed",
            "actions": ["evidence stored", "stored", "evidence released", "released", "evidence destroyed", "destroyed", "sealed by court", "sealed"],
        },
    ]

    ev_tx = evidence.get("tx_hash") or ""
    stages_result = []

    for sdef in stage_defs:
        num = sdef["stage"]
        name = sdef["name"]
        match_actions = sdef["actions"]

        matched_log = None
        for log in custody_logs:
            act = str(log.get("action") or "").strip().lower()
            if act in match_actions:
                # Disambiguate initial registration vs field collection
                if num == 3 and act == "collected" and "initial" in str(log.get("note") or "").lower():
                    continue
                matched_log = log
                break

        # Inferences from record state if specific log hasn't arrived
        if not matched_log:
            if num == 1 and evidence.get("created_at"):
                matched_log = {
                    "action": "Evidence Uploaded / Seizure Initiated",
                    "actor_name": evidence.get("uploader_name") or "Investigator",
                    "actor_role": "investigator",
                    "created_at": evidence.get("created_at"),
                    "tx_hash": ev_tx,
                    "note": f"Seizure under warrant {evidence.get('warrant_number') or 'N/A'}",
                }
            elif num == 2 and evidence.get("witness_signed_at"):
                matched_log = {
                    "action": "Witness Attested",
                    "actor_name": evidence.get("witness_signer_name") or "Witness",
                    "actor_role": "witness",
                    "created_at": evidence.get("witness_signed_at"),
                    "tx_hash": ev_tx,
                    "note": "Two-factor seizure witness attestation confirmed",
                }
            elif num == 7 and evidence.get("status") in ["verified", "tampered"]:
                matched_log = {
                    "action": "Evidence Verified",
                    "actor_name": "Forensic Authority",
                    "actor_role": "analyst",
                    "created_at": evidence.get("created_at"),
                    "tx_hash": ev_tx,
                    "note": f"Status: {evidence.get('status')}",
                }
            elif num == 9 and evidence.get("is_sealed"):
                matched_log = {
                    "action": "Sealed by Court",
                    "actor_name": "Court Authority",
                    "actor_role": "court_authority",
                    "created_at": evidence.get("sealed_at") or evidence.get("created_at"),
                    "tx_hash": ev_tx,
                    "note": "Court-sealed and finalized",
                }

        if matched_log:
            tx = matched_log.get("tx_hash") or ""
            bc_status = resolve_bc_status(tx)
            stages_result.append({
                "stage": num,
                "key": sdef["key"],
                "name": name,
                "status": "completed",
                "blockchain_status": bc_status,
                "tx_hash": tx if bc_status != "Pending" else None,
                "actor": f"{matched_log.get('actor_name') or 'Authorized Actor'} ({matched_log.get('actor_role') or 'authorized'})",
                "timestamp": str(matched_log.get("created_at") or ""),
                "note": matched_log.get("note") or "",
            })
        else:
            stages_result.append({
                "stage": num,
                "key": sdef["key"],
                "name": name,
                "status": "pending",
                "blockchain_status": "Pending",
                "tx_hash": None,
                "actor": None,
                "timestamp": None,
                "note": None,
            })

    return stages_result


@app.route("/api/evidence/<evidence_id>/lifecycle", methods=["GET"])
@login_required
def evidence_lifecycle(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not user_can_access_evidence(user, evidence):
        return jsonify({"error": "Access denied"}), 403

    custody = db.get_custody_logs(evidence_id)
    stages = build_lifecycle_stages(evidence, custody)
    return jsonify({
        "evidence_id": evidence_id,
        "stages": stages,
        "completed_count": len([s for s in stages if s["status"] == "completed"]),
        "total_stages": len(stages),
    })


@app.route("/api/evidence/<evidence_id>", methods=["GET"])
@login_required
def get_evidence(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not user_can_access_evidence(user, evidence):
        return jsonify({"error": "Access denied. Submit access request with legal reason."}), 403

    custody = db.get_custody_logs(evidence_id)
    bc_data, bc_err = blockchain.get_evidence(evidence_id)

    payload = dict(evidence)
    payload["preview"] = build_preview_metadata(evidence_id, payload["file_name"], payload.get("file_path"))
    tx_meta, tx_err = blockchain.get_transaction_info(payload.get("tx_hash") or "")
    payload["tx_metadata"] = tx_meta if tx_meta else {
        "tx_hash": payload.get("tx_hash"),
        "block_number": None,
        "timestamp": None,
        "status": "unknown",
        "source": "database",
        "error": tx_err,
    }

    custody_enriched = []
    for log in custody:
        row = dict(log)
        log_tx_meta, _ = blockchain.get_transaction_info(row.get("tx_hash") or "")
        if log_tx_meta:
            row["tx_metadata"] = log_tx_meta
        custody_enriched.append(row)

    stages = build_lifecycle_stages(evidence, custody)
    payload["lifecycle"] = stages

    latest_anomaly = db.get_latest_anomaly_report(evidence_id)
    payload["anomaly_report"] = dict(latest_anomaly) if latest_anomaly else None

    return jsonify(
        {
            "evidence": payload,
            "custody_logs": custody_enriched,
            "blockchain": bc_data if bc_data else {"error": bc_err},
            "lifecycle": stages,
            "anomaly_report": dict(latest_anomaly) if latest_anomaly else None,
        }
    )


@app.route("/api/evidence/<evidence_id>/file", methods=["GET"])
@login_required
def serve_evidence_file(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not user_can_access_evidence(user, evidence):
        return jsonify({"error": "Access denied. Submit access request with legal reason."}), 403

    if not can_preview(evidence["file_name"]):
        return jsonify({"error": "Preview not supported for this file type"}), 415

    storage_name, abs_path = resolve_storage_file(evidence)
    if not abs_path:
        return jsonify({"error": "Evidence file missing from storage"}), 404

    # Auto-heal stale/dirty DB paths so next access is direct.
    if storage_name != (evidence.get("file_path") or ""):
        db.update_evidence_file_path(evidence_id, storage_name)

    mime_type, _ = mimetypes.guess_type(evidence["file_name"])
    response = send_from_directory(
        UPLOAD_FOLDER,
        storage_name,
        as_attachment=False,
        mimetype=mime_type or "application/octet-stream",
    )
    response.headers["Content-Disposition"] = f'inline; filename="{secure_filename(evidence["file_name"])}"'
    return response


@app.route("/api/verify_evidence", methods=["POST"])
@role_required("analyst", "court_authority", "investigator", "police", "admin")
def verify_evidence():
    evidence_id, current_hash, input_error = resolve_verify_input_or_error()
    if input_error:
        return input_error

    result, err = blockchain.verify_evidence(evidence_id, current_hash)
    if err:
        result, fallback_error = db_fallback_verify_result(evidence_id, current_hash)
        if fallback_error:
            return fallback_error
    else:
        result["source"] = "blockchain"

    evidence = db.get_evidence_by_id(evidence_id)
    if evidence_is_sealed(evidence):
        result["sealed"] = True
    else:
        new_status = "verified" if result["intact"] else "tampered"
        db.update_evidence_status(evidence_id, new_status)

        user = db.get_user_by_id(session["user_id"]) or {}
        actor_name = user.get("name", "Examiner")
        actor_role = user.get("role", "analyst")
        verdict = "PASSED" if result["intact"] else "FAILED"

        tx_meta_ver, bc_err_ver = blockchain.record_custody_action(
            evidence_id,
            "Evidence Verified",
            actor_name=actor_name,
            actor_role=actor_role,
            note=f"Cryptographic hash check: {verdict}",
            case_id=evidence.get("case_id") or "",
        )
        if bc_err_ver:
            tx_meta_ver = offline_tx_meta()

        db.add_custody_log(
            evidence_id,
            "Evidence Verified" if result["intact"] else "Tamper Detected",
            session["user_id"],
            f"Cryptographic hash check: {verdict}",
            tx_meta_ver["tx_hash"],
        )
        result["custody_tx_hash"] = tx_meta_ver["tx_hash"]
        result["custody_tx_metadata"] = tx_meta_ver
        result["custody_blockchain_confirmed"] = bc_err_ver is None

    return jsonify(result)


@app.route("/api/transfer_evidence", methods=["POST"])
@role_required("investigator", "police", "analyst", "court_authority", "admin")
def transfer_evidence():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    required = ["evidence_id", "action", "note"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing fields"}), 400

    valid_actions = [
        # Official 9 Lifecycle Stages
        "Evidence Uploaded / Seizure Initiated",
        "Witness Attested",
        "Evidence Collected",
        "Evidence Transferred",
        "Forensic Analysis Started",
        "Forensic Analysis Completed",
        "Evidence Verified",
        "Evidence Presented to Court",
        "Evidence Stored",
        "Evidence Released",
        "Evidence Destroyed",
        # Standard Aliases
        "Collected",
        "Analyzed",
        "Transferred",
        "Verified",
        "Presented",
        "Stored",
        "Released",
        "Destroyed",
        "Sealed",
        "Sealed by Court",
    ]
    if data["action"] not in valid_actions:
        return jsonify({"error": f"Invalid action. Use one of the lifecycle actions: {', '.join(valid_actions)}"}), 400

    evidence = db.get_evidence_by_id(data["evidence_id"])
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if evidence_is_sealed(evidence):
        return jsonify({"error": "Evidence is court-sealed and immutable"}), 423

    user = db.get_user_by_id(session["user_id"]) or {}
    actor_name = user.get("name", "User")
    actor_role = user.get("role", "authorized")

    tx_meta, bc_err = blockchain.record_custody_action(
        data["evidence_id"],
        data["action"],
        actor_name=actor_name,
        actor_role=actor_role,
        note=data["note"],
        case_id=evidence.get("case_id") or "",
    )
    if bc_err:
        tx_meta = offline_tx_meta()

    tx_hash = tx_meta["tx_hash"]

    db.add_custody_log(data["evidence_id"], data["action"], session["user_id"], data["note"], tx_hash)

    return jsonify(
        {
            "message": "Custody record added",
            "tx_hash": tx_hash,
            "blockchain_recorded": bc_err is None,
            "blockchain_mode": "online" if bc_err is None else "fallback",
            "blockchain_error": bc_err,
            "tx_metadata": tx_meta,
        }
    )


@app.route("/api/evidence/branch", methods=["POST"])
@role_required("analyst", "investigator", "admin")
def branch_evidence():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    parent_evidence_id = request.form.get("parent_evidence_id", "").strip()
    if not parent_evidence_id:
        return jsonify({"error": "parent_evidence_id required"}), 400

    parent = db.get_evidence_by_id(parent_evidence_id)
    if not parent:
        return jsonify({"error": "Parent evidence not found"}), 404
    if evidence_is_sealed(parent):
        return jsonify({"error": "Parent evidence is sealed; no derived evidence can be created"}), 423

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400

    original_filename = secure_filename(file.filename)
    file_bytes = file.read()
    file_size = len(file_bytes)
    if file_size > MAX_EVIDENCE_FILE_SIZE_BYTES:
        return jsonify({"error": f"File too large. Max allowed size is {MAX_EVIDENCE_FILE_SIZE_MB} MB"}), 413

    child_hash = generate_hash_from_bytes(file_bytes)
    child_id = "EV-" + uuid.uuid4().hex[:8].upper()
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S_")
    stored_filename = timestamp_prefix + original_filename
    file_path = os.path.join(UPLOAD_FOLDER, stored_filename)
    with open(file_path, "wb") as out:
        out.write(file_bytes)

    tx_meta_add, bc_err_add = blockchain.add_evidence(
        child_id,
        child_hash,
        original_filename,
        parent.get("case_id") or "CASE-UNKNOWN",
    )
    if bc_err_add:
        tx_meta_add = offline_tx_meta()

    tx_meta_link, bc_err_link = blockchain.transfer_evidence(
        child_id,
        "Derived",
        f"ParentEvidence={parent_evidence_id};ParentHash={parent['file_hash']}",
    )
    if bc_err_link:
        tx_meta_link = offline_tx_meta()

    db.save_evidence(
        child_id,
        original_filename,
        stored_filename,
        file_size,
        child_hash,
        parent.get("case_id"),
        request.form.get("description", "Derived evidence artifact"),
        session["user_id"],
        tx_meta_add["tx_hash"],
        warrant_number=parent.get("warrant_number") or "",
        source_gps=parent.get("source_gps") or "",
        source_device_id=parent.get("source_device_id") or "",
        is_private=bool(parent.get("is_private")),
        parent_evidence_id=parent_evidence_id,
        witness_signed_by=session["user_id"],
    )

    db.add_custody_log(
        child_id,
        "Derived Evidence Created",
        session["user_id"],
        f"Derived from parent {parent_evidence_id} without altering original evidence",
        tx_meta_link["tx_hash"],
    )

    # Record Forensic Analysis Completed on parent evidence on-chain
    user = db.get_user_by_id(session["user_id"]) or {}
    tx_meta_parent, bc_err_parent = blockchain.record_custody_action(
        parent_evidence_id,
        "Forensic Analysis Completed",
        actor_name=user.get("name", "Examiner"),
        actor_role=user.get("role", "analyst"),
        note=f"Derived evidence generated: {child_id} ({child_hash[:16]}...)",
        case_id=parent.get("case_id") or "",
    )
    if bc_err_parent:
        tx_meta_parent = offline_tx_meta()

    db.add_custody_log(
        parent_evidence_id,
        "Forensic Analysis Completed",
        session["user_id"],
        f"Derived evidence generated: {child_id} ({child_hash[:16]}...)",
        tx_meta_parent["tx_hash"],
    )

    return jsonify(
        {
            "message": "Derived evidence branch created",
            "child_evidence_id": child_id,
            "parent_evidence_id": parent_evidence_id,
            "file_hash": child_hash,
            "tx_metadata": {
                "add": tx_meta_add,
                "link": tx_meta_link,
            },
            "blockchain_errors": {
                "add": bc_err_add,
                "link": bc_err_link,
            },
        }
    ), 201


@app.route("/api/evidence/<evidence_id>/request-access", methods=["POST"])
@login_required
def request_private_access(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not evidence.get("is_private"):
        return jsonify({"error": "Evidence is not private; no subpoena request needed"}), 400
    if int(evidence.get("uploaded_by") or 0) == int(user["id"]):
        return jsonify({"error": "Owner already has access"}), 400

    data = request.get_json() or {}
    reason = (data.get("reason") or "").strip()
    if len(reason) < 12:
        return jsonify({"error": "reason must be at least 12 characters"}), 400

    request_id = db.create_access_request(
        evidence_id,
        user["id"],
        evidence["uploaded_by"],
        reason,
    )

    db.add_custody_log(
        evidence_id,
        "Private Access Requested",
        user["id"],
        reason,
    )

    return jsonify({"message": "Access request submitted", "request_id": request_id}), 201


@app.route("/api/evidence/access-requests", methods=["GET"])
@login_required
def list_access_requests():
    return jsonify(db.get_access_requests_for_owner(session["user_id"]))


@app.route("/api/evidence/access-requests/<int:request_id>/review", methods=["POST"])
@login_required
def review_access_request(request_id):
    req = db.get_access_request_by_id(request_id)
    if not req:
        return jsonify({"error": "Access request not found"}), 404
    if int(req["owner_id"]) != int(session["user_id"]):
        return jsonify({"error": "Only evidence owner can review this request"}), 403
    if req["status"] != "pending":
        return jsonify({"error": "Request already reviewed"}), 409

    body = request.get_json() or {}
    decision = (body.get("decision") or "").strip().lower()
    if decision not in {"approved", "rejected"}:
        return jsonify({"error": "decision must be approved or rejected"}), 400

    db.review_access_request(request_id, decision, session["user_id"])
    db.add_custody_log(
        req["evidence_id"],
        "Private Access " + ("Approved" if decision == "approved" else "Rejected"),
        session["user_id"],
        req["reason"],
    )

    return jsonify({"message": f"Request {decision}"})


@app.route("/api/evidence/<evidence_id>/seal", methods=["POST"])
@role_required("court_authority")
def seal_evidence(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if evidence_is_sealed(evidence):
        return jsonify({"error": "Evidence already sealed"}), 409

    tx_meta, bc_err = blockchain.transfer_evidence(
        evidence_id,
        "Sealed",
        "Court-sealed final legal record",
    )
    if bc_err:
        tx_meta = offline_tx_meta()

    sealed = db.seal_evidence(evidence_id, session["user_id"])
    if not sealed:
        return jsonify({"error": "Failed to seal evidence"}), 500

    db.add_custody_log(
        evidence_id,
        "Sealed by Court",
        session["user_id"],
        "Evidence record is now immutable",
        tx_meta["tx_hash"],
    )

    return jsonify(
        {
            "message": "Evidence sealed",
            "evidence_id": evidence_id,
            "tx_metadata": tx_meta,
            "blockchain_error": bc_err,
        }
    )


@app.route("/api/evidence/<evidence_id>/verification-link", methods=["POST"])
@role_required("court_authority")
def create_public_verification_link(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    body = request.get_json() or {}
    expires_minutes = body.get("expires_minutes", 30)
    try:
        expires_minutes = int(expires_minutes)
    except ValueError:
        expires_minutes = 30
    expires_minutes = max(5, min(expires_minutes, 120))

    token = secrets.token_urlsafe(32)
    token_h = hash_token(token)
    expires_at = now_utc() + timedelta(minutes=expires_minutes)
    db.create_verification_link(token_h, evidence_id, session["user_id"], expires_at)

    return jsonify(
        {
            "verification_link": f"{APP_URL}/api/public/verify?token={token}",
            "expires_at": expires_at.isoformat() + "Z",
            "one_time": True,
            "evidence_id": evidence_id,
        }
    )


@app.route("/api/public/verify", methods=["GET", "POST"])
def public_verify_with_link():
    if request.method == "GET":
        token = (request.args.get("token") or "").strip()
    else:
        body = request.get_json(silent=True) or {}
        token = (body.get("token") or "").strip()

    if not token:
        return jsonify({"error": "token required"}), 400

    token_h = hash_token(token)
    link_row = db.consume_verification_link(token_h)
    if not link_row:
        return jsonify({"error": "Invalid, expired, or already-used token"}), 401

    evidence = db.get_evidence_by_id(link_row["evidence_id"])
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    if "file" in request.files:
        candidate_hash = generate_hash_from_bytes(request.files["file"].read())
    else:
        data = request.get_json(silent=True) or {}
        candidate_hash = (data.get("file_hash") or "").strip().lower()
        if not candidate_hash:
            return jsonify({"error": "Provide either a file upload or file_hash in JSON body"}), 400

    stored_hash = (evidence["file_hash"] or "").lower()
    intact = hmac.compare_digest(stored_hash, candidate_hash.lower())

    return jsonify(
        {
            "verified": intact,
            "evidence_id": evidence["evidence_id"],
            "case_id": evidence.get("case_id"),
            "note": "One-time verification completed",
        }
    )


@app.route("/api/evidence_history/<evidence_id>", methods=["GET"])
@login_required
def evidence_history(evidence_id):
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    # Personal audit model for analyst/police/investigator: only files they touched.
    if user["role"] in {"analyst", "police", "investigator"} and not db.user_touched_evidence(evidence_id, user["id"]):
        return jsonify({"error": "Access denied. Personal audit scope only."}), 403

    logs = db.get_custody_logs(evidence_id)
    bc_chain, _ = blockchain.get_custody_chain(evidence_id)
    return jsonify({"evidence_id": evidence_id, "db_logs": logs, "blockchain_logs": bc_chain})


@app.route("/api/dashboard/stats", methods=["GET"])
@login_required
def dashboard_stats():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    if user["role"] == "admin":
        stats = db.get_stats()
        stats["scope"] = "global"
    else:
        stats = db.get_user_stats(user["id"])
        stats["scope"] = "personal"

    stats["role"] = user["role"]
    return jsonify(stats)


@app.route("/api/dashboard/activity", methods=["GET"])
@login_required
def dashboard_activity():
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    limit_raw = request.args.get("limit", "12")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 12
    limit = max(1, min(limit, 50))

    if user["role"] in {"analyst", "police", "investigator"}:
        logs = db.get_recent_activity_for_touched_files(user["id"], limit=limit)
        scope = "personal"
    else:
        logs = db.get_recent_activity(limit=limit, user_id=None)
        scope = "global"

    return jsonify({
        "scope": scope,
        "role": user["role"],
        "logs": logs,
    })


@app.route("/api/evidence/<evidence_id>/access-token", methods=["POST"])
@role_required("admin", "court_authority")
def issue_police_access_token(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    body = request.get_json() or {}
    expires_minutes = body.get("expires_minutes", 30)
    max_uses = body.get("max_uses", 1)
    note = (body.get("note") or "Token-gated police access").strip()
    try:
        expires_minutes = int(expires_minutes)
    except ValueError:
        expires_minutes = 30
    try:
        max_uses = int(max_uses)
    except ValueError:
        max_uses = 1

    expires_minutes = max(5, min(expires_minutes, 240))
    max_uses = max(1, min(max_uses, 10))

    token = secrets.token_urlsafe(24)
    token_h = hash_token(token)
    expires_at = now_utc() + timedelta(minutes=expires_minutes)
    token_id = db.create_police_access_token(
        evidence_id,
        token_h,
        session["user_id"],
        note,
        expires_at,
        max_uses=max_uses,
    )
    if not token_id:
        return jsonify({"error": "Failed to issue access token"}), 500

    return jsonify(
        {
            "message": "Access token issued",
            "evidence_id": evidence_id,
            "token": token,
            "expires_at": expires_at.isoformat() + "Z",
            "max_uses": max_uses,
            "note": note,
        }
    ), 201


@app.route("/api/evidence/<evidence_id>/use-token", methods=["POST"])
@role_required("police")
def use_police_token(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    if int(evidence.get("uploaded_by") or 0) == int(session["user_id"]):
        return jsonify({"message": "Own evidence does not require token"}), 200

    body = request.get_json() or {}
    token = (body.get("token") or "").strip()
    if not token:
        return jsonify({"error": "token required"}), 400

    token_row = db.use_police_access_token(evidence_id, hash_token(token))
    if not token_row:
        return jsonify({"error": "Invalid/expired/exhausted token"}), 401

    note = token_row.get("note") or "Police token-gate access"
    tx_meta, bc_err = blockchain.transfer_evidence(
        evidence_id,
        "GrantAccess",
        f"PoliceTokenAccess by user={session['user_id']}; reason={note}",
    )
    if bc_err:
        tx_meta = offline_tx_meta()

    db.add_police_access_grant(
        evidence_id,
        session["user_id"],
        token_row["id"],
        token_row.get("issued_by"),
        note,
        tx_meta["tx_hash"],
    )

    db.add_custody_log(
        evidence_id,
        "GrantAccess",
        session["user_id"],
        f"Token-gate access granted: {note}",
        tx_meta["tx_hash"],
    )

    return jsonify(
        {
            "message": "Token accepted. Access granted.",
            "evidence_id": evidence_id,
            "tx_metadata": tx_meta,
            "blockchain_error": bc_err,
        }
    )


@app.route("/api/admin/timeline-by-user", methods=["GET"])
@role_required("admin")
def admin_timeline_by_user():
    limit_raw = request.args.get("limit", "200")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 200
    limit = max(20, min(limit, 500))

    logs = db.get_admin_timeline_by_user(limit=limit)
    grouped = {}
    for row in logs:
        actor_id = str(row.get("user_id") or "system")
        actor_key = f"{actor_id}:{row.get('actor_name') or 'System'}"
        if actor_key not in grouped:
            grouped[actor_key] = {
                "actor_id": row.get("user_id"),
                "actor_name": row.get("actor_name") or "System",
                "actor_role": row.get("actor_role") or "unknown",
                "events": [],
            }
        grouped[actor_key]["events"].append(dict(row))

    return jsonify({"groups": list(grouped.values()), "total_events": len(logs)})


@app.route("/api/admin/super-view/users", methods=["GET"])
@role_required("admin")
def admin_super_view_users():
    return jsonify(db.get_non_admin_users())


@app.route("/api/admin/super-view/<int:user_id>/folders", methods=["GET"])
@role_required("admin")
def admin_super_view_folders(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    evidence_rows = db.get_evidence_by_uploader(user_id)
    tree = {}
    for item in evidence_rows:
        created = item.get("created_at")
        if created is None:
            continue
        year = f"{created.year:04d}"
        month = f"{created.month:02d}"
        day = f"{created.day:02d}"
        tree.setdefault(year, {})
        tree[year].setdefault(month, {})
        tree[year][month].setdefault(day, [])
        tree[year][month][day].append(
            {
                "evidence_id": item["evidence_id"],
                "file_name": item["file_name"],
                "status": item.get("status"),
                "created_at": item.get("created_at"),
            }
        )

    return jsonify({
        "user": {
            "id": user["id"],
            "name": user["name"],
            "role": user["role"],
        },
        "folders": tree,
        "total_evidence": len(evidence_rows),
    })


@app.route("/api/admin/super-view/evidence/<evidence_id>/timeline", methods=["GET"])
@role_required("admin")
def admin_super_view_evidence_timeline(evidence_id):
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404

    uploader_id = evidence.get("uploaded_by")
    system_logs = db.get_system_logs_for_user(uploader_id, limit=200) if uploader_id else []
    evidence_logs = db.get_custody_logs(evidence_id)

    timeline = []
    append_system_timeline_events(timeline, system_logs, evidence.get("created_at"))
    append_evidence_timeline_events(timeline, evidence_logs)
    append_blockchain_timeline_events(timeline, evidence, evidence_logs)

    timeline.sort(key=lambda x: x.get("timestamp") or datetime.min)

    return jsonify(
        {
            "evidence": {
                "evidence_id": evidence.get("evidence_id"),
                "file_name": evidence.get("file_name"),
                "uploaded_by": evidence.get("uploader_name"),
                "created_at": evidence.get("created_at"),
                "status": evidence.get("status"),
            },
            "timeline": timeline,
        }
    )


# Admin API
@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
def admin_users():
    return jsonify(db.get_all_users())


@app.route("/api/admin/create-user", methods=["POST"])
@role_required("admin")
def admin_create_user():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    required = ["name", "email", "password", "role"]
    if not all(k in data and data[k] for k in required):
        return jsonify({"error": "Missing required fields: name, email, password, role"}), 400

    valid_roles = ["investigator", "police", "analyst", "court_authority", "witness", "admin"]
    if data["role"] not in valid_roles:
        return jsonify({"error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"}), 400

    if len(data["password"]) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    hashed = hash_password(data["password"])
    success = db.create_user(
        data["name"].strip(),
        data["email"].strip().lower(),
        hashed,
        data["role"],
        data.get("wallet_address", "").strip(),
    )
    if not success:
        return jsonify({"error": "User with this email already exists"}), 409

    return jsonify({"message": f"User {data['email']} ({data['role']}) created successfully"}), 201


@app.route("/api/admin/users/<int:user_id>/disable", methods=["POST"])
@role_required("admin")
def admin_disable_user(user_id):
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    if len(reason) < 12:
        return jsonify({"error": "A detailed reason (min 12 chars) is required for deactivation request"}), 400

    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Admin account cannot be disabled"}), 400
    if user["role"] != "investigator":
        return jsonify({"error": "Multi-sig deactivation endpoint is restricted to investigator accounts"}), 400
    if user["id"] == session.get("user_id"):
        return jsonify({"error": "You cannot disable your own account"}), 400

    action_id = db.create_admin_action("deactivate_user", user_id, session["user_id"], reason)
    if not action_id:
        return jsonify({"error": "Failed to create admin action request"}), 500

    return jsonify(
        {
            "message": "Deactivation request created. Second admin approval required.",
            "action_id": action_id,
            "status": "pending",
        }
    ), 202


@app.route("/api/admin/users/<int:user_id>/enable", methods=["POST"])
@role_required("admin")
def admin_enable_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    updated = db.set_user_active(user_id, True)
    if not updated:
        return jsonify({"error": "Failed to enable user"}), 500
    return jsonify({"message": "User enabled"})


@app.route("/api/admin/actions/pending", methods=["GET"])
@role_required("admin")
def list_pending_admin_actions():
    return jsonify(db.get_pending_admin_actions())


@app.route("/api/admin/actions/<int:action_id>/approve", methods=["POST"])
@role_required("admin")
def approve_admin_action(action_id):
    action = db.get_admin_action_by_id(action_id)
    if not action:
        return jsonify({"error": "Admin action not found"}), 404
    if action["status"] != "pending":
        return jsonify({"error": "Action is no longer pending"}), 409
    if int(action["requested_by"]) == int(session["user_id"]):
        return jsonify({"error": "Requester cannot self-approve admin action"}), 403

    if action["action_type"] == "deactivate_user":
        target = db.get_user_by_id(action["target_user_id"])
        if not target:
            return jsonify({"error": "Target user not found"}), 404
        if target["role"] != "investigator":
            return jsonify({"error": "Target is no longer an investigator"}), 409

        updated = db.set_user_active(action["target_user_id"], False)
        if not updated:
            return jsonify({"error": "Failed to deactivate target user"}), 500
    else:
        return jsonify({"error": "Unsupported admin action type"}), 400

    approved = db.approve_admin_action(action_id, session["user_id"])
    if not approved:
        return jsonify({"error": "Failed to mark action as approved"}), 500

    return jsonify({"message": "Admin action approved and executed"})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@role_required("admin")
def admin_delete_user(user_id):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user["role"] == "admin":
        return jsonify({"error": "Admin account cannot be deleted"}), 400
    if user["id"] == session.get("user_id"):
        return jsonify({"error": "You cannot delete your own account"}), 400

    can_delete, evidence_count, logs_count = db.can_delete_user(user_id)
    if not can_delete:
        return jsonify({
            "error": "Cannot delete user with linked evidence or custody records. Disable instead.",
            "linked_evidence": evidence_count,
            "linked_logs": logs_count,
        }), 409

    deleted = db.delete_user(user_id)
    if not deleted:
        return jsonify({"error": "Failed to delete user"}), 500
    return jsonify({"message": "User deleted"})


@app.route("/api/admin/stats", methods=["GET"])
@role_required("admin")
def stats():
    return jsonify(db.get_stats())


@app.route("/api/admin/logs", methods=["GET"])
@role_required("admin")
def all_logs():
    return jsonify(db.get_all_custody_logs())


@app.route("/api/admin/suspicious-activity", methods=["GET"])
@role_required("admin")
def admin_suspicious_activity():
    limit_raw = request.args.get("limit", "50")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))
    return jsonify(db.get_suspicious_activity(limit=limit))


@app.route("/api/admin/system-health", methods=["GET"])
@role_required("admin")
def admin_system_health():
    return jsonify(get_system_health_snapshot())


@app.route("/api/blockchain/info", methods=["GET"])
@login_required
def blockchain_info():
    return jsonify(blockchain.get_network_info())


@app.route("/api/blockchain/deploy", methods=["POST"])
@role_required("admin")
def deploy_contract():
    address, err = blockchain.deploy_contract()
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"message": "Contract deployed", "address": address})


@app.route("/api/blockchain/set_address", methods=["POST"])
@role_required("admin")
def set_contract_address():
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400
    if "address" not in data:
        return jsonify({"error": "address required"}), 400

    success = blockchain.set_contract_address(data["address"])
    if not success:
        return jsonify({"error": "Invalid address"}), 400

    return jsonify({"message": "Contract address updated"})


# ── Feature 1: Merkle Tree Batching API Endpoints ───────────────────────────
@app.route("/api/merkle/batch", methods=["POST"])
@role_required("admin")
def create_merkle_batch():
    """Create a Merkle Tree batch from an array of file hashes or uploaded files, and commit root on-chain.
    Existing file-upload workflow — preserved as-is.
    """
    data = request.get_json(silent=True) or {}
    case_id = (data.get("case_id") or request.form.get("case_id") or "BATCH-CASE-001").strip()
    hashes = data.get("hashes", [])

    # Support multiple file uploads in request.files
    if "files" in request.files:
        files = request.files.getlist("files")
        for f in files:
            if f.filename:
                content = f.read()
                h = generate_hash_from_bytes(content)
                hashes.append(h)

    if not hashes:
        return jsonify({"error": "No hashes or files provided for batching"}), 400

    root_hex, proofs, leaves = blockchain.MerkleTreeHelper.build_tree(hashes)
    count = len(hashes)

    # Commit Merkle Root on-chain
    tx_meta, err = blockchain.commit_merkle_batch(root_hex, count, case_id)
    tx_hash = tx_meta.get("tx_hash") if tx_meta else f"OFFLINE-ROOT-{secrets.token_hex(8)}"

    # Store batch record in DB
    user_id = session.get("user_id")
    batch_label = db.get_next_batch_label()
    batch_id = db.create_merkle_batch(root_hex, count, case_id, user_id, tx_hash, batch_label)

    return jsonify({
        "message": f"Merkle Tree batch with {count} items committed successfully!",
        "batch_id": batch_id,
        "batch_label": batch_label,
        "root_hash": root_hex,
        "item_count": count,
        "case_id": case_id,
        "tx_hash": tx_hash,
        "blockchain_status": "offline" if (tx_hash or "").startswith("OFFLINE") else "confirmed",
        "onchain_meta": tx_meta,
        "proofs": proofs,
        "leaves": leaves
    }), 201


@app.route("/api/merkle/batch/evidence", methods=["POST"])
@role_required("admin")
def create_merkle_batch_from_evidence():
    """Create a Merkle Tree batch from selected existing evidence records (using stored file_hash).
    Admin selects evidence IDs; their stored hashes become the Merkle leaves.
    The original evidence records and hashes are NOT modified.
    """
    import json as json_mod
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    evidence_ids = data.get("evidence_ids", [])
    case_id = (data.get("case_id") or "BATCH-EVIDENCE-001").strip()

    if not evidence_ids or len(evidence_ids) < 1:
        return jsonify({"error": "Select at least 1 evidence record to batch"}), 400

    # Fetch each evidence record and extract its file_hash
    hashes = []
    evidence_meta = []
    for ev_id in evidence_ids:
        ev = db.get_evidence_by_id(ev_id)
        if not ev:
            return jsonify({"error": f"Evidence '{ev_id}' not found"}), 404
        file_hash = ev.get("file_hash") or ev.get("hash")
        if not file_hash:
            return jsonify({"error": f"Evidence '{ev_id}' has no stored file hash — cannot include in Merkle batch"}), 422
        hashes.append(file_hash)
        evidence_meta.append({"evidence_id": ev_id, "file_hash": file_hash, "title": ev.get("title", ev_id)})

    # Build Merkle tree from evidence hashes
    root_hex, proofs, leaves = blockchain.MerkleTreeHelper.build_tree(hashes)
    count = len(hashes)

    # Guard against duplicate batch commitment (both on-chain and in DB)
    existing = db.get_merkle_batch_by_root(root_hex)
    if existing:
        ex_label = existing.get("batch_label") or f"MB-{existing['id']}"
        return jsonify({
            "error": f"A Merkle batch containing this exact evidence set has already been committed as '{ex_label}'.",
            "batch_id": existing["id"],
            "batch_label": ex_label
        }), 409

    # Commit Merkle Root on-chain
    tx_meta, err = blockchain.commit_merkle_batch(root_hex, count, case_id)
    tx_hash = tx_meta.get("tx_hash") if tx_meta else f"OFFLINE-ROOT-{secrets.token_hex(8)}"
    blockchain_status = "offline" if (tx_hash or "").startswith("OFFLINE") else "confirmed"

    # Build per-item records (store proofs so verification is instant later)
    user_id = session.get("user_id")
    batch_label = db.get_next_batch_label()

    evidence_items = []
    for i, meta in enumerate(evidence_meta):
        leaf_hex = leaves[i] if i < len(leaves) else ("0x" + meta["file_hash"])
        # Look up proof by leaf hex or raw hash key
        raw_key = leaf_hex[2:] if leaf_hex.startswith("0x") else leaf_hex
        proof_arr = proofs.get(raw_key) or proofs.get(leaf_hex) or proofs.get(meta["file_hash"]) or []
        evidence_items.append({
            "evidence_id": meta["evidence_id"],
            "leaf_hash": leaf_hex,
            "leaf_index": i,
            "proof_json": json_mod.dumps(proof_arr)
        })

    batch_id = db.create_merkle_batch_from_evidence(
        root_hex, count, case_id, user_id, tx_hash, evidence_items, batch_label
    )
    if not batch_id:
        return jsonify({"error": "Failed to save Merkle batch records to database"}), 500


    # Build response with per-item details
    items_response = []
    for i, meta in enumerate(evidence_meta):
        leaf_hex = leaves[i] if i < len(leaves) else ("0x" + meta["file_hash"])
        raw_key = leaf_hex[2:] if leaf_hex.startswith("0x") else leaf_hex
        proof_arr = proofs.get(raw_key) or proofs.get(leaf_hex) or proofs.get(meta["file_hash"]) or []
        items_response.append({
            "evidence_id": meta["evidence_id"],
            "title": meta["title"],
            "leaf_hash": leaf_hex,
            "leaf_index": i,
            "proof": proof_arr
        })

    return jsonify({
        "message": f"Merkle batch '{batch_label}' with {count} evidence items committed successfully!",
        "batch_id": batch_id,
        "batch_label": batch_label,
        "root_hash": root_hex,
        "item_count": count,
        "case_id": case_id,
        "tx_hash": tx_hash,
        "blockchain_status": blockchain_status,
        "onchain_meta": tx_meta,
        "items": items_response
    }), 201


@app.route("/api/merkle/batch/<int:batch_id>/items", methods=["GET"])
@role_required("admin", "court_authority")
def get_merkle_batch_items(batch_id):
    """Return all evidence items belonging to a specific Merkle batch."""
    batch = db.get_merkle_batch_by_id(batch_id)
    if not batch:
        return jsonify({"error": f"Merkle batch #{batch_id} not found"}), 404
    items = db.get_merkle_batch_items(batch_id)
    return jsonify({
        "batch_id": batch_id,
        "batch_label": batch.get("batch_label") or f"MB-{batch_id:03d}",
        "root_hash": batch.get("root_hash"),
        "case_id": batch.get("case_id"),
        "tx_hash": batch.get("tx_hash"),
        "item_count": batch.get("item_count"),
        "committer_name": batch.get("committer_name"),
        "created_at": str(batch.get("created_at")),
        "items": [dict(it) for it in items]
    })


@app.route("/api/merkle/batch/<int:batch_id>/verify-evidence", methods=["POST"])
@role_required("admin", "court_authority")
def verify_evidence_in_batch(batch_id):
    """Verify that a specific evidence record is cryptographically included in a Merkle batch.
    Uses the stored proof from merkle_batch_items — does NOT modify any evidence record.
    """
    import json as json_mod
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    evidence_id = (data.get("evidence_id") or "").strip()
    if not evidence_id:
        return jsonify({"error": "evidence_id is required"}), 400

    # Fetch batch
    batch = db.get_merkle_batch_by_id(batch_id)
    if not batch:
        return jsonify({"error": f"Merkle batch #{batch_id} not found"}), 404

    # Fetch stored item record
    item = db.get_merkle_item_by_evidence(batch_id, evidence_id)
    if not item:
        return jsonify({
            "valid": False,
            "evidence_id": evidence_id,
            "batch_id": batch_id,
            "batch_label": batch.get("batch_label") or f"MB-{batch_id:03d}",
            "error": f"Evidence '{evidence_id}' was not included in batch #{batch_id}",
            "result": "NOT_IN_BATCH"
        }), 404

    # Load stored proof and leaf hash
    leaf_hash = item.get("leaf_hash", "")
    root_hash = batch.get("root_hash", "")
    try:
        proof_list = json_mod.loads(item.get("proof_json") or "[]")
    except Exception:
        proof_list = []

    # Verify via blockchain (with off-chain fallback)
    valid, err = blockchain.verify_merkle_proof(leaf_hash, proof_list, root_hash)

    return jsonify({
        "valid": bool(valid),
        "evidence_id": evidence_id,
        "batch_id": batch_id,
        "batch_label": batch.get("batch_label") or f"MB-{batch_id:03d}",
        "leaf_hash": leaf_hash,
        "root_hash": root_hash,
        "proof_length": len(proof_list),
        "tx_hash": batch.get("tx_hash"),
        "blockchain_verified": bool(valid) and not (batch.get("tx_hash") or "").startswith("OFFLINE"),
        "result": "VALID" if valid else "INTEGRITY_CHECK_FAILED",
        "error": err
    })


@app.route("/api/merkle/verify", methods=["POST"])
@role_required("admin", "analyst", "court_authority")
def verify_merkle_proof_api():
    """Verify an individual file hash against a committed Merkle Root on-chain."""
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    leaf_hash = data.get("leaf_hash")
    proof_list = data.get("proof")
    root_hex = data.get("root_hash")

    if not leaf_hash or not proof_list or not root_hex:
        return jsonify({"error": "Missing leaf_hash, proof, or root_hash"}), 400

    valid, err = blockchain.verify_merkle_proof(leaf_hash, proof_list, root_hex)
    return jsonify({
        "valid": bool(valid),
        "leaf_hash": leaf_hash,
        "root_hash": root_hex,
        "proof_length": len(proof_list),
        "error": err
    })


@app.route("/api/merkle/batches", methods=["GET"])
@role_required("admin", "court_authority")
def get_merkle_batches():
    """Return all committed Merkle Tree batches. Admin sees all; Court Authority sees all (read-only)."""
    batches = db.get_all_merkle_batches()
    result = []
    for b in batches:
        row = dict(b)
        # Derive display label if not stored
        if not row.get("batch_label"):
            row["batch_label"] = f"MB-{row['id']:03d}"
        row["blockchain_status"] = "offline" if (row.get("tx_hash") or "").startswith("OFFLINE") else "confirmed"
        result.append(row)
    return jsonify(result)


# ── Feature 2: Expiring Smart Warrants API Endpoints ────────────────────────
@app.route("/api/warrants/register", methods=["POST"])
@role_required("court_authority", "admin", "investigator", "police")
def register_smart_warrant():
    """Court Authority / Admin registers a search warrant with on-chain expiration timer."""
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    warrant_number = (data.get("warrant_number") or "").strip()
    case_id = (data.get("case_id") or "").strip()
    duration_seconds = int(data.get("duration_seconds") or 86400) # Default 1 day

    if not warrant_number or not case_id:
        return jsonify({"error": "warrant_number and case_id are required"}), 400

    if duration_seconds <= 0:
        return jsonify({"error": "duration_seconds must be greater than 0"}), 400

    from datetime import datetime, timedelta
    valid_until = datetime.now() + timedelta(seconds=duration_seconds)
    user_id = session.get("user_id")

    # Register on-chain
    tx_meta, err = blockchain.register_warrant(warrant_number, case_id, duration_seconds)
    tx_hash = tx_meta.get("tx_hash") if tx_meta else f"OFFLINE-WARRANT-{secrets.token_hex(8)}"

    # Store in DB
    w_id = db.create_warrant(warrant_number, case_id, user_id, duration_seconds, valid_until, tx_hash)
    if not w_id:
        return jsonify({"error": f"Warrant '{warrant_number}' already registered"}), 409

    return jsonify({
        "message": f"Smart Warrant '{warrant_number}' issued successfully",
        "warrant_id": w_id,
        "warrant_number": warrant_number,
        "case_id": case_id,
        "duration_seconds": duration_seconds,
        "valid_until": valid_until.isoformat(),
        "tx_hash": tx_hash,
        "onchain_meta": tx_meta
    }), 201


def parse_datetime(val):
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val)
        except Exception:
            pass
        try:
            from dateutil import parser
            return parser.parse(val)
        except Exception:
            pass
    return None


@app.route("/api/warrants", methods=["GET"])
@login_required
def list_smart_warrants():
    """List all warrants with live validity status, start time, and extension audit records."""
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404

    # Witness has no Smart Warrant access
    if user["role"] == "witness":
        return jsonify({"error": "Witness role has no access to Smart Warrants"}), 403

    warrants = db.get_all_warrants()
    now = datetime.now()

    result = []
    for w in warrants:
        valid_until = parse_datetime(w.get("valid_until"))

        is_valid = False
        seconds_remaining = 0
        if valid_until:
            diff = (valid_until - now).total_seconds()
            is_valid = diff > 0
            seconds_remaining = max(0, int(diff))

        w_copy = dict(w)
        w_copy["is_valid"] = is_valid
        w_copy["seconds_remaining"] = seconds_remaining
        w_copy["status"] = "active" if is_valid else "expired"
        w_copy["start_time"] = str(w.get("created_at") or "")

        # Attach extension requests & pending status
        ext_requests = db.get_warrant_extension_requests(warrant_number=w.get("warrant_number"))
        pending_req = next((r for r in ext_requests if r.get("status") == "pending"), None)
        w_copy["pending_extension"] = pending_req is not None
        w_copy["pending_request"] = pending_req
        w_copy["extension_history"] = ext_requests

        # Attach latest AI recommendation if available
        if hasattr(db, "get_latest_warrant_ai_recommendation"):
            latest_rec = db.get_latest_warrant_ai_recommendation(w.get("warrant_number"))
            w_copy["ai_recommendation"] = dict(latest_rec) if latest_rec else None
        else:
            w_copy["ai_recommendation"] = None

        result.append(w_copy)

    return jsonify(result)


@app.route("/api/warrants/<string:warrant_number>", methods=["GET"])
@login_required
def get_smart_warrant_detail(warrant_number):
    """Get single warrant details and verify on-chain status."""
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user["role"] == "witness":
        return jsonify({"error": "Witness role has no access to Smart Warrants"}), 403

    w = db.get_warrant_by_number(warrant_number)
    if not w:
        return jsonify({"error": "Warrant not found"}), 404

    now = datetime.now()
    valid_until = parse_datetime(w.get("valid_until"))

    diff = (valid_until - now).total_seconds() if valid_until else 0
    onchain_valid, _ = blockchain.is_warrant_valid(warrant_number)

    ext_requests = db.get_warrant_extension_requests(warrant_number=warrant_number)
    pending_req = next((r for r in ext_requests if r.get("status") == "pending"), None)

    latest_rec = db.get_latest_warrant_ai_recommendation(warrant_number) if hasattr(db, "get_latest_warrant_ai_recommendation") else None

    res = dict(w)
    res["is_valid"] = (diff > 0) and onchain_valid
    res["seconds_remaining"] = max(0, int(diff))
    res["onchain_valid"] = onchain_valid
    res["start_time"] = str(w.get("created_at") or "")
    res["pending_extension"] = pending_req is not None
    res["pending_request"] = pending_req
    res["extension_history"] = ext_requests
    res["ai_recommendation"] = dict(latest_rec) if latest_rec else None
    return jsonify(res)



@app.route("/api/warrants/<string:warrant_number>/request-extension", methods=["POST"])
@role_required("police", "investigator", "admin")
def request_warrant_extension(warrant_number):
    """Police/Investigator requests a warrant extension with mandatory reason."""
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    reason = (data.get("reason") or "").strip()
    if not reason:
        return jsonify({"error": "Extension reason is mandatory"}), 400

    w = db.get_warrant_by_number(warrant_number)
    if not w:
        return jsonify({"error": "Warrant not found"}), 404

    current_expiry = parse_datetime(w.get("valid_until"))
    if not current_expiry:
        current_expiry = datetime.now()

    # Calculate requested expiry and additional seconds
    additional_seconds = int(data.get("additional_seconds") or 0)
    requested_expiry_str = data.get("requested_expiry")

    from datetime import timedelta
    if requested_expiry_str:
        requested_expiry = parse_datetime(requested_expiry_str)
        if not requested_expiry or requested_expiry <= current_expiry:
            return jsonify({"error": "Requested expiry must be a valid timestamp beyond current expiry"}), 400
        additional_seconds = int((requested_expiry - current_expiry).total_seconds())
    elif additional_seconds > 0:
        base_time = current_expiry if current_expiry > datetime.now() else datetime.now()
        requested_expiry = base_time + timedelta(seconds=additional_seconds)
    else:
        return jsonify({"error": "Must specify additional_seconds (> 0) or requested_expiry"}), 400

    user_id = session.get("user_id")
    req_id, err = db.create_warrant_extension_request(
        warrant_number=warrant_number,
        requester_id=user_id,
        current_expiry=current_expiry,
        requested_expiry=requested_expiry,
        additional_seconds=additional_seconds,
        reason=reason
    )
    if err:
        return jsonify({"error": err}), 409

    return jsonify({
        "message": f"Extension request for warrant '{warrant_number}' submitted for Court Approval",
        "request_id": req_id,
        "warrant_number": warrant_number,
        "current_expiry": current_expiry.isoformat(),
        "requested_expiry": requested_expiry.isoformat(),
        "additional_seconds": additional_seconds,
        "reason": reason,
        "status": "pending"
    }), 201


@app.route("/api/warrants/extension-requests", methods=["GET"])
@role_required("court_authority", "admin", "police", "investigator")
def list_warrant_extension_requests():
    """List warrant extension requests. Filtered by officer for police/investigator."""
    user = db.get_user_by_id(session["user_id"])
    role = user.get("role")
    status_filter = request.args.get("status")
    warrant_number = request.args.get("warrant_number")

    requester_id = user["id"] if role in ["police", "investigator"] else None
    requests_list = db.get_warrant_extension_requests(
        warrant_number=warrant_number,
        status=status_filter,
        requester_id=requester_id
    )
    return jsonify(requests_list)


@app.route("/api/warrants/extension-requests/<int:request_id>/review", methods=["POST"])
@role_required("court_authority", "admin")
def review_warrant_extension(request_id):
    """Court Authority / Admin approves or rejects a warrant extension request."""
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    decision = (data.get("decision") or "").strip().lower()
    if decision not in ["approved", "rejected"]:
        return jsonify({"error": "decision must be 'approved' or 'rejected'"}), 400

    decision_note = (data.get("decision_note") or "").strip()
    req_record = db.get_warrant_extension_request_by_id(request_id)
    if not req_record:
        return jsonify({"error": "Extension request not found"}), 404

    if req_record.get("status") != "pending":
        return jsonify({"error": f"Request has already been {req_record.get('status')}"}), 409

    # Conflict of interest check: officer cannot approve their own request
    user_id = session.get("user_id")
    if int(req_record.get("requester_id") or 0) == int(user_id):
        return jsonify({"error": "Conflict of interest: You cannot approve your own extension request"}), 403

    warrant_number = req_record["warrant_number"]
    additional_seconds = int(req_record["additional_seconds"])
    requested_expiry = parse_datetime(req_record["requested_expiry"])

    tx_hash = None
    tx_meta = None
    if decision == "approved":
        # Extend on blockchain via smart contract
        tx_meta, bc_err = blockchain.extend_warrant(warrant_number, additional_seconds)
        if bc_err:
            app.logger.warning("Blockchain warrant extension error: %s", bc_err)
            tx_meta = offline_tx_meta()

        tx_hash = tx_meta.get("tx_hash")
        # Update active expiry in DB
        db.db_extend_warrant(warrant_number, additional_seconds, requested_expiry)

    # Record review decision in DB
    success = db.review_warrant_extension_request(
        request_id=request_id,
        reviewer_id=user_id,
        decision=decision,
        decision_note=decision_note,
        tx_hash=tx_hash
    )
    if not success:
        return jsonify({"error": "Failed to record extension review"}), 500

    # Record final human decision on AI recommendation records
    if hasattr(db, "update_warrant_ai_recommendation_decision"):
        db.update_warrant_ai_recommendation_decision(warrant_number, decision, user_id)

    return jsonify({
        "message": f"Warrant extension request {decision} successfully",
        "request_id": request_id,
        "decision": decision,
        "warrant_number": warrant_number,
        "new_valid_until": requested_expiry.isoformat() if decision == "approved" else None,
        "tx_hash": tx_hash,
        "tx_meta": tx_meta,
        "decision_note": decision_note
    })


@app.route("/api/warrants/<string:warrant_number>/ai-recommendation", methods=["GET", "POST"])
@login_required
def get_warrant_ai_recommendation_api(warrant_number):
    """
    Generates an advisory AI recommendation for smart warrant extension based on
    case workflow completion, pending evidence/verification, and remaining validity.
    Strictly advisory: only Court Authority can approve or reject extensions.
    """
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user.get("role") == "witness":
        return jsonify({"error": "Witness role has no access to Smart Warrants"}), 403

    try:
        from ai.warrant_advisor import generate_warrant_recommendation
        payload, err, status_code = generate_warrant_recommendation(warrant_number, user)
        if err:
            return jsonify({"error": err}), status_code
        return jsonify(payload), 200
    except Exception as e:
        app.logger.error("Warrant AI recommendation error: %s", str(e))
        return jsonify({
            "error": f"Failed to generate warrant recommendation: {str(e)}",
            "available": False
        }), 500


@app.route("/api/warrants/<string:warrant_number>/extend", methods=["POST"])
@role_required("court_authority", "admin")
def extend_smart_warrant(warrant_number):
    """Direct warrant extension by Court Authority / Admin (preserved for backward compatibility)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": ERR_INVALID_REQUEST_BODY}), 400

    additional_seconds = int(data.get("additional_seconds") or 86400)
    if additional_seconds <= 0:
        return jsonify({"error": "additional_seconds must be greater than 0"}), 400

    w = db.get_warrant_by_number(warrant_number)
    if not w:
        return jsonify({"error": "Warrant not found"}), 404

    old_until = parse_datetime(w.get("valid_until"))
    if not old_until:
        old_until = datetime.now()

    from datetime import timedelta
    new_until = (old_until if old_until > datetime.now() else datetime.now()) + timedelta(seconds=additional_seconds)

    # Extend on-chain
    tx_meta, err = blockchain.extend_warrant(warrant_number, additional_seconds)
    # Update DB
    db.db_extend_warrant(warrant_number, additional_seconds, new_until)

    return jsonify({
        "message": f"Warrant '{warrant_number}' extended by {additional_seconds} seconds",
        "warrant_number": warrant_number,
        "new_valid_until": new_until.isoformat(),
        "tx_meta": tx_meta
    })


# ── Feature: ML Anomaly Detection Endpoints ─────────────────────────────────

def run_evidence_anomaly_scan(evidence_id, auto_record_blockchain=False):
    """
    Executes feature extraction and Isolation Forest inference for a specific evidence record.
    Persists report in database, logs model execution time, and optionally records on-chain alert.
    Never modifies evidence records or hashes.
    """
    import json as json_mod
    import time

    start_time = time.time()
    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return {"error": ERR_EVIDENCE_NOT_FOUND, "available": False}, 404

    # Graceful degradation if ML engine is not available
    if not ml_detector or not extract_evidence_features or not ml_detector.is_available:
        return {
            "evidence_id": evidence_id,
            "available": False,
            "message": "AI analysis unavailable (Isolation Forest model uninitialized)",
            "anomaly_score": 0.0,
            "is_anomaly": False,
            "risk_level": "UNKNOWN",
            "status": "AI Analysis Unavailable",
            "reasons": ["Isolation Forest anomaly detector is currently not initialized."],
            "model_version": getattr(ml_detector, "model_version", "unavailable") if ml_detector else "unavailable"
        }, 200

    custody_logs = db.get_custody_logs(evidence_id)
    access_entries = db.get_access_entries(evidence_id) if hasattr(db, "get_access_entries") else []

    # Convert sqlite3.Row objects to plain dicts for the feature extractor (.get() compatibility)
    custody_logs_dicts = [dict(row) for row in (custody_logs or [])]
    access_entries_dicts = [dict(row) for row in (access_entries or [])]
    evidence_dict = dict(evidence) if evidence and not isinstance(evidence, dict) else (evidence or {})

    feature_vector, feature_dict, explanations = extract_evidence_features(evidence_dict, custody_logs_dicts, access_entries_dicts)

    prediction = ml_detector.predict(feature_vector, explanations)
    execution_time_ms = round((time.time() - start_time) * 1000.0, 2)

    # Persist report in database
    report_id = db.save_ml_anomaly_report(
        evidence_id=evidence_id,
        anomaly_score=prediction["anomaly_score"],
        is_anomaly=prediction["is_anomaly"],
        risk_level=prediction["risk_level"],
        status=prediction["status"],
        reasons_json=json_mod.dumps(prediction["reasons"]),
        features_json=json_mod.dumps(feature_dict),
        model_version=prediction["model_version"]
    )

    # Log model execution for audit provenance
    db.log_ml_execution(
        model_version=prediction["model_version"],
        evidence_id=evidence_id,
        score=prediction["anomaly_score"],
        risk_level=prediction["risk_level"],
        execution_time_ms=execution_time_ms
    )

    # Optional on-chain alert for high-risk anomalies (does NOT modify evidence hashes)
    tx_hash = None
    if auto_record_blockchain and prediction["is_anomaly"] and prediction["risk_level"] == "HIGH":
        try:
            alert_note = f"AI Anomaly Detected: {prediction['status']} | Score: {prediction['anomaly_score']} | " + "; ".join(prediction["reasons"][:2])
            tx_meta, _ = blockchain.record_custody_action(
                evidence_id=evidence_id,
                action="AI Anomaly Detected",
                actor_name="AI Anomaly Sentinel (Isolation Forest)",
                actor_role="system",
                note=alert_note[:250],
                case_id=evidence.get("case_id")
            )
            tx_hash = tx_meta.get("tx_hash") if tx_meta else None
        except Exception as bc_e:
            app.logger.warning("Failed to record AI Anomaly on-chain: %s", bc_e)

    result = {
        "report_id": report_id,
        "evidence_id": evidence_id,
        "case_id": evidence.get("case_id"),
        "title": evidence.get("title"),
        "available": True,
        "anomaly_score": prediction["anomaly_score"],
        "is_anomaly": prediction["is_anomaly"],
        "risk_level": prediction["risk_level"],
        "status": prediction["status"],
        "reasons": prediction["reasons"],
        "features": feature_dict,
        "model_version": prediction["model_version"],
        "execution_time_ms": execution_time_ms,
        "onchain_alert_tx": tx_hash,
        "disclaimer": "Advisory Layer: AI/ML anomaly detection is an auxiliary heuristic. Cryptographic blockchain verification remains the authoritative legal evidence integrity standard."
    }
    return result, 200


@app.route("/api/ml/evidence/<evidence_id>/analyze", methods=["GET", "POST"])
@login_required
def analyze_evidence_anomaly(evidence_id):
    """Trigger on-demand real-time Isolation Forest scan on an evidence record."""
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user.get("role") == "witness":
        return jsonify({"error": "Witness role has no access to AI anomaly module"}), 403

    evidence = db.get_evidence_by_id(evidence_id)
    if not evidence:
        return jsonify({"error": ERR_EVIDENCE_NOT_FOUND}), 404
    if not user_can_access_evidence(user, evidence):
        return jsonify({"error": "Access denied for this evidence"}), 403

    auto_bc = request.args.get("record_blockchain", "false").lower() == "true" or (request.get_json(silent=True) or {}).get("record_blockchain", False)
    # Admin or analyst can trigger on-chain sentinel alert
    if auto_bc and user.get("role") not in {"admin", "analyst"}:
        auto_bc = False

    result, code = run_evidence_anomaly_scan(evidence_id, auto_record_blockchain=auto_bc)
    return jsonify(result), code


@app.route("/api/ml/anomalies", methods=["GET"])
@login_required
def get_ml_anomalies():
    """List anomaly reports scoped by user role."""
    import json as json_mod
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user.get("role") == "witness":
        return jsonify({"error": "Witness role has no access to AI anomaly module"}), 403

    all_reports = db.get_all_anomaly_reports()
    user_role = user.get("role")

    filtered = []
    for r in all_reports:
        row = dict(r)
        # Check authorization if not admin
        if user_role != "admin":
            ev = db.get_evidence_by_id(row["evidence_id"])
            if not ev or not user_can_access_evidence(user, ev):
                continue

        # Parse JSON fields safely
        try:
            row["reasons"] = json_mod.loads(row.get("reasons_json") or "[]")
        except Exception:
            row["reasons"] = []
        try:
            row["features"] = json_mod.loads(row.get("features_json") or "{}")
        except Exception:
            row["features"] = {}

        filtered.append(row)

    return jsonify(filtered)


@app.route("/api/ml/reports/<int:report_id>/review", methods=["POST"])
@role_required("admin")
def review_anomaly_report_api(report_id):
    """Admin reviews an anomaly alert and records resolution (benign or investigation)."""
    data = request.get_json() or {}
    review_status = (data.get("review_status") or "").strip().lower()
    valid_statuses = {"reviewed_benign", "flagged_investigation", "reviewed"}
    if review_status not in valid_statuses:
        return jsonify({"error": f"review_status must be one of: {', '.join(valid_statuses)}"}), 400

    review_notes = (data.get("review_notes") or "").strip()
    user_id = session.get("user_id")

    success = db.review_anomaly_report(
        report_id=report_id,
        reviewed_by=user_id,
        review_status=review_status,
        review_notes=review_notes
    )
    if not success:
        return jsonify({"error": f"Anomaly report #{report_id} not found"}), 404

    return jsonify({
        "message": f"Anomaly report #{report_id} reviewed successfully",
        "report_id": report_id,
        "review_status": review_status,
        "review_notes": review_notes
    })


@app.route("/api/ml/train", methods=["POST"])
@role_required("admin")
def retrain_ml_model_api():
    """Admin triggers retraining/recalibration of the Isolation Forest model."""
    try:
        try:
            from ml.eviblock_train_model import train_and_evaluate_eviblock_model
            train_and_evaluate_eviblock_model()
        except ImportError:
            from ml.train_model import train_isolation_forest
            train_isolation_forest()
        if ml_detector:
            ml_detector.load_model()
        return jsonify({
            "message": "EviBlock Isolation Forest anomaly detector retrained and loaded successfully",
            "model_version": getattr(ml_detector, "model_version", "v2.0-eviblock-isolation-forest"),
            "status": "ready"
        }), 200
    except Exception as e:
        return jsonify({"error": f"Training failed: {str(e)}"}), 500


@app.route("/api/ml/status", methods=["GET"])
@login_required
def get_ml_status():
    """Returns status and readiness of the Isolation Forest detector."""
    user = db.get_user_by_id(session["user_id"])
    if not user or user.get("role") == "witness":
        return jsonify({"error": "Unauthorized"}), 403

    available = bool(ml_detector and ml_detector.is_available)
    return jsonify({
        "available": available,
        "model_type": "Isolation Forest (Unsupervised)",
        "model_version": getattr(ml_detector, "model_version", "unavailable") if ml_detector else "unavailable",
        "contamination": 0.10,
        "feature_count": 12,
        "disclaimer": "Advisory Layer: AI/ML anomaly detection is an auxiliary heuristic. Cryptographic blockchain verification remains the authoritative legal evidence integrity standard."
    })


@app.route("/api/ml/logs", methods=["GET"])
@role_required("admin")
def get_ml_logs_api():
    """Returns recent ML model execution logs for audit provenance."""
    limit = int(request.args.get("limit") or 50)
    logs = db.get_ml_model_logs(limit=limit)
    return jsonify([dict(l) for l in logs])


# ── Feature: AI Case Summary Endpoints ─────────────────────────────────────


@app.route("/api/cases", methods=["GET"])
@login_required
def list_cases_api():
    """Lists distinct case IDs that the currently authenticated user has authorization to view."""
    user = db.get_user_by_id(session["user_id"])
    if not user or user.get("role") == "witness":
        return jsonify({"error": "Witness role is restricted from case summary access"}), 403

    role = user.get("role")
    if role in {"admin", "court_authority"}:
        case_ids = db.get_distinct_case_ids()
        return jsonify({"cases": case_ids})

    # For police, investigator, analyst: filter cases where user has access to at least 1 evidence
    all_evidence = db.get_all_evidence()
    accessible_cases = set()
    for ev in all_evidence:
        if user_can_access_evidence(user, ev):
            c_id = ev.get("case_id")
            if c_id and c_id.strip():
                accessible_cases.add(c_id.strip())

    return jsonify({"cases": sorted(list(accessible_cases))})


@app.route("/api/cases/<path:case_id>/summary", methods=["GET", "POST"])
@login_required
def get_case_summary_api(case_id):
    """
    Generates an objective, structured AI Case Summary aggregating database,
    custody timeline, blockchain anchoring, and smart warrant data.
    """
    user = db.get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": ERR_USER_NOT_FOUND}), 404
    if user.get("role") == "witness":
        return jsonify({"error": "Access Denied: Witness role is restricted from case summary generation"}), 403

    try:
        from ai.case_summary import generate_case_summary
        summary, err, status_code = generate_case_summary(case_id, user)
        if err:
            return jsonify({"error": err}), status_code
        return jsonify(summary), 200
    except Exception as e:
        app.logger.error("Case summary generation error: %s", str(e))
        return jsonify({
            "error": f"Failed to generate case summary: {str(e)}",
            "available": False
        }), 500


if __name__ == "__main__":


    print("=" * 60)
    print("  ForensicChain - Blockchain Evidence Management System")
    print("=" * 60)
    print("  Server:     http://localhost:5000")
    print(f"  Blockchain: {blockchain.is_connected and 'Connected' or 'Not connected (offline mode)'}")
    print(f"  Contract:   {blockchain.contract_address or 'Not deployed'}")
    print("=" * 60)

    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
        host=host,
        port=port,
    )
