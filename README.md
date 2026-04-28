# SecureAuth

A Flask web application demonstrating modern authentication: live password-rule
validation, salted bcrypt hashing, email-based two-factor authentication,
IP-based rate limiting, signed sessions, and a real-time analytics dashboard.

## Run locally

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Visit http://127.0.0.1:5000

## Test users

```powershell
python seed.py
```

| Username | Password | Role |
|----------|----------|------|
| admin | AdminPassword123! | admin |
| testuser | TestPassword123! | user |
| alice | AlicePassword123! | user |
| bob | BobPassword123! | user |
| demo | DemoPassword123! | user |

The 6-digit email code is printed in the Flask console window unless SMTP
credentials are configured (see `.env.example`).

## Deploy to Render

1. Push this repo to GitHub.
2. Create a free Web Service on render.com, connect it to your GitHub repo.
3. Render auto-detects `Procfile` and `requirements.txt`.
4. Add these environment variables in the Render dashboard:
   - `SECRET_KEY` — any long random string
   - (optional) `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` for real emails
5. Deploy. Render provisions HTTPS automatically via Let's Encrypt.

The app auto-seeds the test users on first run if the database is empty.
