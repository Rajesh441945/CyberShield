# CyberShield V2 - Secure Deployment Version

## Local run
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py

## Render deployment
Build Command:
pip install -r requirements.txt

Start Command:
gunicorn app:app

Environment variables:
SECRET_KEY=<long-random-secret>
ADMIN_USERNAME=<private-admin-username>
ADMIN_PASSWORD=<private-admin-password>

Do NOT put these values in app.py, HTML, README, GitHub, screenshots, or public posts.

## Important database note
This version still uses SQLite. On Render Free, the local filesystem is ephemeral, so the SQLite database can be reset when the service restarts/redeploys/spins down. This is acceptable for a temporary college demonstration, but use a persistent PostgreSQL database for a real multi-user deployment.

## Security note
Use a strong unique admin password. The login page no longer displays the credentials.
