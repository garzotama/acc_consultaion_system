
# ACC Consultation System

A complete Flask + SQLite role-based consultation request system for **Abuyog Community College (ACC)**.

## Stack

- Python 3.10+
- Flask
- SQLite
- Jinja2
- HTML5 + CSS3
- Werkzeug password hashing

## Roles

**Super Admin**
- Manage Medical and Student accounts
- Activate/deactivate/delete users
- View and manage all consultation requests
- Assign Medical staff
- Update consultation status
- View system-wide reports and activity

**Medical Staff**
- View assigned requests
- Accept/respond to requests
- Update status and add notes
- View consultation history

**Student**
- Register and log in
- Submit consultation requests
- View status/history
- Read Medical responses

## Setup

1. Open the extracted project folder in VS Code.
2. Create a virtual environment:

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize and seed the database:
```bash
python seed.py
```

5. Start the server:
```bash
python app.py
```

6. Open:
```text
http://127.0.0.1:5000
```

## Default test credentials

| Role | Username | Password |
|---|---|---|
| Super Admin | `admin` | `Admin@123` |
| Medical Staff | `medical` | `Medical@123` |
| Student | `student` | `Student@123` |

## Typical workflow

1. Student submits a consultation.
2. Super Admin sees it in Consultations.
3. Super Admin assigns it to Medical staff.
4. Medical staff opens the assigned request.
5. Medical staff updates status and writes a response.
6. Student sees the new status/response.
7. Super Admin monitors overall activity in Reports.

## Security notes

This starter project includes hashed passwords, session authentication, server-side RBAC, ownership checks, inactive-account blocking, SQLite foreign keys, and basic validation.

For production, add CSRF protection, use a strong environment-provided SECRET_KEY, disable debug mode, use HTTPS, configure secure cookies, and add production backups/logging.
