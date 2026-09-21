from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import sqlite3, re, math, os
from urllib.parse import urlparse
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
DB = "cybershield.db"
FAILED_LIMIT = 5
LOCKOUT_MINUTES = 10

def get_db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = get_db()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS security_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,event_type TEXT NOT NULL,severity TEXT NOT NULL,
        message TEXT NOT NULL,created_at TEXT NOT NULL)""")
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if admin_username and admin_password:
        if not c.execute("SELECT id FROM users WHERE username=?", (admin_username,)).fetchone():
            c.execute(
                "INSERT INTO users(username,password_hash) VALUES(?,?)",
                (admin_username, generate_password_hash(admin_password))
            )
    c.commit(); c.close()

def add_event(user, typ, severity, message):
    c=get_db()
    c.execute("""INSERT INTO security_events
        (username,event_type,severity,message,created_at)
        VALUES(?,?,?,?,?)""",
        (user,typ,severity,message,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    c.commit(); c.close()

def password_check(p):
    score=0; suggestions=[]
    if len(p)>=8: score+=1
    else: suggestions.append("Use at least 8 characters.")
    if len(p)>=12: score+=1
    if re.search(r"[A-Z]",p): score+=1
    else: suggestions.append("Add an uppercase letter.")
    if re.search(r"[a-z]",p): score+=1
    else: suggestions.append("Add a lowercase letter.")
    if re.search(r"\d",p): score+=1
    else: suggestions.append("Add a number.")
    if re.search(r"[^A-Za-z0-9]",p): score+=1
    else: suggestions.append("Add a special character.")
    if p.lower() in {"password","password123","123456","12345678","qwerty","admin","admin123"}:
        return {"score":0,"level":"Very Weak","entropy":0,
                "suggestions":["This is a commonly used password. Choose a unique password."]}
    level="Weak" if score<=2 else "Medium" if score<=4 else "Strong"
    charset=sum([26 if re.search(r"[a-z]",p) else 0,
                 26 if re.search(r"[A-Z]",p) else 0,
                 10 if re.search(r"\d",p) else 0,
                 32 if re.search(r"[^A-Za-z0-9]",p) else 0])
    entropy=round(len(p)*math.log2(charset),1) if charset and p else 0
    return {"score":score,"level":level,"entropy":entropy,"suggestions":suggestions}

def url_check(value):
    value=value.strip()
    if not value:
        return {"url":"","risk_score":0,"level":"Invalid",
                "risks":["Please enter a URL."],
                "recommendation":"Enter a complete URL or domain."}
    test=value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",value) else "http://"+value
    p=urlparse(test); host=p.hostname or ""; risks=[]; score=0
    if p.scheme not in ("http","https"): risks.append("Unsupported or unusual URL scheme."); score+=2
    if p.scheme=="http": risks.append("The URL uses HTTP instead of HTTPS."); score+=1
    if "@" in p.netloc: risks.append("The URL contains '@', which can hide the real destination."); score+=2
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",host): risks.append("The hostname is an IP address instead of a normal domain."); score+=2
    if host.startswith("xn--") or ".xn--" in host: risks.append("The domain uses punycode; verify the domain carefully."); score+=2
    if len(value)>100: risks.append("The URL is unusually long."); score+=1
    words=["login","verify","verification","secure","account","update","password","bank","confirm","signin"]
    if len([w for w in words if w in value.lower()])>=2:
        risks.append("The URL contains multiple words commonly seen in account/phishing lures."); score+=1
    if host.count("-")>=3: risks.append("The domain contains many hyphens; verify the spelling."); score+=1
    if p.username: risks.append("The URL includes embedded user information."); score+=1
    if not host or "." not in host: risks.append("The hostname does not look like a normal public domain."); score+=2
    level="High Risk" if score>=4 else "Medium Risk" if score>=2 else "Low Risk"
    return {"url":value,"risk_score":min(score,10),"level":level,"risks":risks,
            "recommendation":"Do not open the link until you verify the domain through a trusted source."
            if score>=2 else "No obvious risk indicators were detected by these basic checks. Still verify the domain before entering sensitive information.",
            "domain":host,"scheme":p.scheme}

def stats():
    c=get_db()
    q=lambda sql:c.execute(sql).fetchone()["c"]
    d={"total":q("SELECT COUNT(*) c FROM security_events"),
       "high":q("SELECT COUNT(*) c FROM security_events WHERE severity='HIGH'"),
       "medium":q("SELECT COUNT(*) c FROM security_events WHERE severity='MEDIUM'"),
       "low":q("SELECT COUNT(*) c FROM security_events WHERE severity='LOW'"),
       "failed":q("SELECT COUNT(*) c FROM security_events WHERE event_type='LOGIN_FAILURE'"),
       "url_checks":q("SELECT COUNT(*) c FROM security_events WHERE event_type='URL_CHECK'"),
       "password_checks":q("SELECT COUNT(*) c FROM security_events WHERE event_type='PASSWORD_CHECK'"),
       "success_logins":q("SELECT COUNT(*) c FROM security_events WHERE event_type='LOGIN_SUCCESS'")}
    c.close()
    d["security_score"]=max(0,min(100,100-min(d["failed"]*5,40)-min(d["high"]*5,25)-min(d["medium"]*2,15)))
    return d

@app.route("/")
def index(): return render_template("index.html")

@app.route("/url-checker",methods=["GET","POST"])
def url_checker():
    r=None
    if request.method=="POST":
        v=request.form.get("url",""); r=url_check(v)
        sev="HIGH" if r["risk_score"]>=4 else "MEDIUM" if r["risk_score"]>=2 else "LOW"
        add_event(session.get("username","guest"),"URL_CHECK",sev,f"Checked URL: {v[:150]}")
    return render_template("url_checker.html",result=r)

@app.route("/password-checker",methods=["GET","POST"])
def password_checker():
    r=None
    if request.method=="POST":
        p=request.form.get("password",""); r=password_check(p)
        add_event(session.get("username","guest"),"PASSWORD_CHECK",
                  "HIGH" if r["level"] in ("Weak","Very Weak") else "LOW",
                  f"Password strength checked: {r['level']}")
    return render_template("password_checker.html",result=r)

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        c=get_db(); user=c.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
        if not user:
            c.close(); add_event(u or "unknown","LOGIN_FAILURE","MEDIUM","Login attempted with unknown username.")
            flash("Invalid username or password.","danger"); return redirect(url_for("login"))
        if user["locked_until"]:
            try:
                until=datetime.fromisoformat(user["locked_until"])
                if datetime.now()<until:
                    mins=max(1,int((until-datetime.now()).total_seconds()//60))
                    c.close(); flash(f"Account temporarily locked. Try again in about {mins} minute(s).","danger")
                    return redirect(url_for("login"))
            except ValueError: pass
        if check_password_hash(user["password_hash"],p):
            c.execute("UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?",(user["id"],))
            c.commit(); c.close(); session["username"]=u
            add_event(u,"LOGIN_SUCCESS","LOW","Successful login."); flash("Login successful.","success")
            return redirect(url_for("dashboard"))
        failed=user["failed_attempts"]+1
        if failed>=FAILED_LIMIT:
            locked=datetime.now()+timedelta(minutes=LOCKOUT_MINUTES)
            c.execute("UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",(failed,locked.isoformat(),user["id"]))
            sev="HIGH"; msg=f"Account locked after {failed} failed login attempts."
        else:
            c.execute("UPDATE users SET failed_attempts=? WHERE id=?",(failed,user["id"]))
            sev="MEDIUM"; msg=f"Failed login attempt #{failed}."
        c.commit(); c.close(); add_event(u,"LOGIN_FAILURE",sev,msg); flash("Invalid username or password.","danger")
    return render_template("login.html")

@app.route("/logout")
def logout(): session.pop("username",None); return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    sev=request.args.get("severity","ALL").upper()
    if sev not in {"ALL","LOW","MEDIUM","HIGH"}: sev="ALL"
    c=get_db()
    if sev=="ALL":
        rows=c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 30").fetchall()
    else:
        rows=c.execute("SELECT * FROM security_events WHERE severity=? ORDER BY id DESC LIMIT 30",(sev,)).fetchall()
    c.close()
    return render_template("dashboard.html",stats=stats(),recent=rows,selected_severity=sev)

@app.route("/report")
def report():
    c=get_db(); events=c.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 100").fetchall(); c.close()
    return render_template("report.html",stats=stats(),events=events,
                           generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/api/stats")
def api_stats(): return jsonify(stats())

@app.route("/api/url-check",methods=["POST"])
def api_url_check():
    data=request.get_json(silent=True) or {}; v=data.get("url","")
    return (jsonify({"error":"URL is required"}),400) if not v else jsonify(url_check(v))

if __name__=="__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
