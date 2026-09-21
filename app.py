from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import sqlite3
import re
import math
import os
from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "cybershield.db")

FAILED_LIMIT = 5
LOCKOUT_MINUTES = 10


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create/migrate tables and create the private administrator account."""
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)

    # Migration for an older CyberShield database that has no role column.
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }
    if "role" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
        )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    # The admin account is created/updated only from private environment variables.
    # No admin credentials are displayed anywhere in the website.
    if admin_username and admin_password:
        existing = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (admin_username,)
        ).fetchone()

        password_hash = generate_password_hash(admin_password)

        if existing:
            conn.execute(
                """
                UPDATE users
                SET role='admin', password_hash=?,
                    failed_attempts=0, locked_until=NULL
                WHERE id=?
                """,
                (password_hash, existing["id"])
            )
        else:
            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, role)
                VALUES (?, ?, 'admin')
                """,
                (admin_username, password_hash)
            )

    conn.commit()
    conn.close()


# Required for Gunicorn/Render: this runs when app.py is imported.
init_db()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            flash("This area is not available for your account.", "danger")
            return redirect(url_for("user_dashboard"))

        return view(*args, **kwargs)
    return wrapped


def add_event(username, event_type, severity, message):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO security_events
        (username, event_type, severity, message, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            username,
            event_type,
            severity,
            message,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )
    conn.commit()
    conn.close()


def password_check(password):
    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add an uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add a lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add a number.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Add a special character.")

    common = {
        "password", "password123", "123456",
        "12345678", "qwerty", "admin", "admin123"
    }

    if password.lower() in common:
        return {
            "score": 0,
            "level": "Very Weak",
            "entropy": 0,
            "suggestions": [
                "This is a commonly used password. Choose a unique password."
            ]
        }

    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"\d", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    entropy = round(len(password) * math.log2(charset), 1) if password and charset else 0
    level = "Weak" if score <= 2 else "Medium" if score <= 4 else "Strong"

    return {
        "score": score,
        "level": level,
        "entropy": entropy,
        "suggestions": suggestions
    }


def url_check(value):
    value = value.strip()

    if not value:
        return {
            "url": "",
            "risk_score": 0,
            "level": "Invalid",
            "risks": ["Please enter a URL."],
            "recommendation": "Enter a URL or domain."
        }

    test_url = value
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", test_url):
        test_url = "http://" + test_url

    parsed = urlparse(test_url)
    host = parsed.hostname or ""
    risks = []
    score = 0

    if parsed.scheme not in ("http", "https"):
        risks.append("Unsupported or unusual URL scheme.")
        score += 2

    if parsed.scheme == "http":
        risks.append("The URL uses HTTP instead of HTTPS.")
        score += 1

    if "@" in parsed.netloc:
        risks.append("The URL contains '@', which can hide the real destination.")
        score += 2

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        risks.append("The hostname is an IP address instead of a normal domain.")
        score += 2

    if host.startswith("xn--") or ".xn--" in host:
        risks.append("The domain uses punycode; verify the domain carefully.")
        score += 2

    if len(value) > 100:
        risks.append("The URL is unusually long.")
        score += 1

    suspicious_words = [
        "login", "verify", "verification", "secure",
        "account", "update", "password", "bank",
        "confirm", "signin"
    ]

    if sum(1 for word in suspicious_words if word in value.lower()) >= 2:
        risks.append(
            "The URL contains multiple words commonly seen in "
            "account or phishing lures."
        )
        score += 1

    if host.count("-") >= 3:
        risks.append("The domain contains many hyphens; verify the spelling.")
        score += 1

    if parsed.username:
        risks.append("The URL contains embedded user information.")
        score += 1

    if not host or "." not in host:
        risks.append("The hostname does not look like a normal public domain.")
        score += 2

    level = "High Risk" if score >= 4 else "Medium Risk" if score >= 2 else "Low Risk"

    recommendation = (
        "Do not open the link until you verify the domain through a trusted source."
        if score >= 2
        else
        "No obvious risk indicators were detected by these basic checks. "
        "Still verify the domain before entering sensitive information."
    )

    return {
        "url": value,
        "risk_score": min(score, 10),
        "level": level,
        "risks": risks,
        "recommendation": recommendation,
        "domain": host,
        "scheme": parsed.scheme
    }


def get_stats():
    conn = get_db()

    def count(sql, params=()):
        return conn.execute(sql, params).fetchone()["count"]

    data = {
        "total": count("SELECT COUNT(*) AS count FROM security_events"),
        "high": count(
            "SELECT COUNT(*) AS count FROM security_events WHERE severity='HIGH'"
        ),
        "medium": count(
            "SELECT COUNT(*) AS count FROM security_events WHERE severity='MEDIUM'"
        ),
        "low": count(
            "SELECT COUNT(*) AS count FROM security_events WHERE severity='LOW'"
        ),
        "failed": count(
            "SELECT COUNT(*) AS count FROM security_events "
            "WHERE event_type='LOGIN_FAILURE'"
        ),
        "url_checks": count(
            "SELECT COUNT(*) AS count FROM security_events "
            "WHERE event_type='URL_CHECK'"
        ),
        "password_checks": count(
            "SELECT COUNT(*) AS count FROM security_events "
            "WHERE event_type='PASSWORD_CHECK'"
        ),
        "success_logins": count(
            "SELECT COUNT(*) AS count FROM security_events "
            "WHERE event_type='LOGIN_SUCCESS'"
        )
    }

    conn.close()

    score = (
        100
        - min(data["failed"] * 5, 40)
        - min(data["high"] * 5, 25)
        - min(data["medium"] * 2, 15)
    )

    data["security_score"] = max(0, min(100, score))
    return data


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("Username must contain at least 3 characters.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if existing:
            conn.close()
            flash("That username is already in use.", "danger")
            return redirect(url_for("register"))

        # Every self-registered account is always a normal user.
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, role)
            VALUES (?, ?, 'user')
            """,
            (username, generate_password_hash(password))
        )
        conn.commit()
        conn.close()

        flash("Account created. You can now sign in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if not user:
            conn.close()
            add_event(
                username or "unknown",
                "LOGIN_FAILURE",
                "MEDIUM",
                "Login attempted with unknown username."
            )
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        if user["locked_until"]:
            try:
                locked_until = datetime.fromisoformat(user["locked_until"])
                if datetime.now() < locked_until:
                    remaining = max(
                        1,
                        int((locked_until - datetime.now()).total_seconds() // 60)
                    )
                    conn.close()
                    flash(
                        f"Account temporarily locked. Try again in about {remaining} minute(s).",
                        "danger"
                    )
                    return redirect(url_for("login"))
            except ValueError:
                pass

        if check_password_hash(user["password_hash"], password):
            conn.execute(
                """
                UPDATE users
                SET failed_attempts=0, locked_until=NULL
                WHERE id=?
                """,
                (user["id"],)
            )
            conn.commit()
            conn.close()

            session.clear()
            session["username"] = username
            session["role"] = user["role"]

            add_event(username, "LOGIN_SUCCESS", "LOW", "Successful login.")

            flash("Login successful.", "success")

            if user["role"] == "admin":
                return redirect(url_for("dashboard"))

            return redirect(url_for("user_dashboard"))

        failed = user["failed_attempts"] + 1

        if failed >= FAILED_LIMIT:
            locked_until = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
            conn.execute(
                """
                UPDATE users
                SET failed_attempts=?, locked_until=?
                WHERE id=?
                """,
                (failed, locked_until.isoformat(), user["id"])
            )
            severity = "HIGH"
            message = f"Account locked after {failed} failed login attempts."
        else:
            conn.execute(
                "UPDATE users SET failed_attempts=? WHERE id=?",
                (failed, user["id"])
            )
            severity = "MEDIUM"
            message = f"Failed login attempt #{failed}."

        conn.commit()
        conn.close()

        add_event(username, "LOGIN_FAILURE", severity, message)
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/user-dashboard")
@login_required
def user_dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("dashboard"))

    username = session["username"]
    conn = get_db()

    events = conn.execute(
        """
        SELECT * FROM security_events
        WHERE username=?
        ORDER BY id DESC
        LIMIT 20
        """,
        (username,)
    ).fetchall()

    conn.close()

    return render_template(
        "user_dashboard.html",
        events=events,
        username=username
    )


@app.route("/dashboard")
@admin_required
def dashboard():
    selected = request.args.get("severity", "ALL").upper()

    if selected not in {"ALL", "LOW", "MEDIUM", "HIGH"}:
        selected = "ALL"

    conn = get_db()

    if selected == "ALL":
        events = conn.execute(
            """
            SELECT * FROM security_events
            ORDER BY id DESC
            LIMIT 30
            """
        ).fetchall()
    else:
        events = conn.execute(
            """
            SELECT * FROM security_events
            WHERE severity=?
            ORDER BY id DESC
            LIMIT 30
            """,
            (selected,)
        ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        stats=get_stats(),
        recent=events,
        selected_severity=selected
    )


@app.route("/report")
@admin_required
def report():
    conn = get_db()
    events = conn.execute(
        """
        SELECT * FROM security_events
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()
    conn.close()

    return render_template(
        "report.html",
        stats=get_stats(),
        events=events,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


@app.route("/url-checker", methods=["GET", "POST"])
def url_checker():
    result = None

    if request.method == "POST":
        value = request.form.get("url", "")
        result = url_check(value)

        severity = (
            "HIGH" if result["risk_score"] >= 4
            else "MEDIUM" if result["risk_score"] >= 2
            else "LOW"
        )

        add_event(
            session.get("username", "guest"),
            "URL_CHECK",
            severity,
            f"Checked URL: {value[:150]}"
        )

    return render_template("url_checker.html", result=result)


@app.route("/password-checker", methods=["GET", "POST"])
def password_checker():
    result = None

    if request.method == "POST":
        password = request.form.get("password", "")
        result = password_check(password)

        severity = (
            "HIGH" if result["level"] in ("Weak", "Very Weak")
            else "LOW"
        )

        # Never store the actual password.
        add_event(
            session.get("username", "guest"),
            "PASSWORD_CHECK",
            severity,
            f"Password strength checked: {result['level']}"
        )

    return render_template("password_checker.html", result=result)


@app.route("/api/stats")
@admin_required
def api_stats():
    return jsonify(get_stats())


@app.route("/api/url-check", methods=["POST"])
def api_url_check():
    data = request.get_json(silent=True) or {}
    value = data.get("url", "")

    if not value:
        return jsonify({"error": "URL is required"}), 400

    return jsonify(url_check(value))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
