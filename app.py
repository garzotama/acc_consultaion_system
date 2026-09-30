
from functools import wraps
from datetime import datetime

from flask import (
    Flask, abort, flash, g, redirect, render_template,
    request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import get_db, init_db, log_activity

app = Flask(__name__)
app.config.from_object(Config)

# Make sure the database tables exist whenever the application starts.
with app.app_context():
    init_db()

ROLE_LABELS = {
    "super_admin": "Super Admin",
    "medical": "Medical Staff",
    "student": "Student",
}

CONSULTATION_STATUSES = [
    "Pending",
    "Accepted",
    "In Progress",
    "Completed",
    "Cancelled",
]


@app.template_filter("role_label")
def role_label(role):
    return ROLE_LABELS.get(role, role)


@app.context_processor
def inject_globals():
    return {"current_user": g.get("user"), "now": datetime.now()}


@app.before_request
def load_logged_in_user():
    """Load the authenticated user from the signed Flask session."""
    user_id = session.get("user_id")
    g.user = None

    if user_id:
        with get_db() as db:
            g.user = db.execute(
                """
                SELECT id, username, full_name, email, role, is_active, created_at
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

        # Deactivated users cannot continue using an existing session.
        if g.user is None or not g.user["is_active"]:
            session.clear()
            g.user = None


def login_required(view):
    """Protect a route so only logged-in users can access it."""
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view


def role_required(*roles):
    """Protect a route with server-side role-based access control."""
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            if g.user["role"] not in roles:
                abort(403)
            return view(**kwargs)
        return wrapped_view
    return decorator


def get_consultation_or_404(consultation_id):
    """Fetch a consultation with student/medical names or return 404."""
    with get_db() as db:
        consultation = db.execute(
            """
            SELECT c.*,
                   s.full_name AS student_name,
                   s.email AS student_email,
                   m.full_name AS medical_name,
                   m.email AS medical_email
            FROM consultations c
            JOIN users s ON s.id = c.student_id
            LEFT JOIN users m ON m.id = c.medical_id
            WHERE c.id = ?
            """,
            (consultation_id,),
        ).fetchone()

    if consultation is None:
        abort(404)
    return consultation


@app.route("/")
def index():
    if g.user:
        return redirect(url_for(f"{g.user['role']}_dashboard"))
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@app.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for(f"{g.user['role']}_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        error = None

        if not username or not password:
            error = "Username and password are required."
        else:
            with get_db() as db:
                user = db.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()

            if user is None or not check_password_hash(
                user["password_hash"], password
            ):
                error = "Invalid username or password."
            elif not user["is_active"]:
                error = "This account is inactive. Contact the Super Admin."

        if error:
            flash(error, "danger")
        else:
            session.clear()
            session["user_id"] = user["id"]
            log_activity(user["id"], "LOGIN", "User logged in")
            flash(f"Welcome, {user['full_name']}!", "success")
            return redirect(url_for(f"{user['role']}_dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    user_id = g.user["id"]
    log_activity(user_id, "LOGOUT", "User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=("GET", "POST"))
def register():
    """Public registration is intentionally limited to Student accounts."""
    if g.user:
        return redirect(url_for(f"{g.user['role']}_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        error = None

        if not username or not full_name or not email or not password:
            error = "All fields are required."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm_password:
            error = "Passwords do not match."

        if error:
            flash(error, "danger")
        else:
            try:
                with get_db() as db:
                    new_id = db.execute(
                        """
                        INSERT INTO users
                            (username, password_hash, full_name, email, role)
                        VALUES (?, ?, ?, ?, 'student')
                        """,
                        (username, generate_password_hash(password), full_name, email),
                    ).lastrowid

                log_activity(new_id, "REGISTER", "Student account registered")
                flash("Registration successful. You can now log in.", "success")
                return redirect(url_for("login"))
            except Exception:
                flash("Username or email is already registered.", "danger")

    return render_template("register.html")


# ---------------------------------------------------------------------------
# Super Admin
# ---------------------------------------------------------------------------

@app.route("/admin")
@role_required("super_admin")
def super_admin_dashboard():
    with get_db() as db:
        stats = {
            "users": db.execute(
                "SELECT COUNT(*) AS count FROM users WHERE is_active = 1"
            ).fetchone()["count"],
            "students": db.execute(
                "SELECT COUNT(*) AS count FROM users "
                "WHERE role = 'student' AND is_active = 1"
            ).fetchone()["count"],
            "medical": db.execute(
                "SELECT COUNT(*) AS count FROM users "
                "WHERE role = 'medical' AND is_active = 1"
            ).fetchone()["count"],
            "consultations": db.execute(
                "SELECT COUNT(*) AS count FROM consultations"
            ).fetchone()["count"],
            "pending": db.execute(
                "SELECT COUNT(*) AS count FROM consultations WHERE status = 'Pending'"
            ).fetchone()["count"],
            "completed": db.execute(
                "SELECT COUNT(*) AS count FROM consultations WHERE status = 'Completed'"
            ).fetchone()["count"],
        }

        recent = db.execute(
            """
            SELECT c.*, s.full_name AS student_name, m.full_name AS medical_name
            FROM consultations c
            JOIN users s ON s.id = c.student_id
            LEFT JOIN users m ON m.id = c.medical_id
            ORDER BY c.created_at DESC LIMIT 8
            """
        ).fetchall()

    return render_template("admin/dashboard.html", stats=stats, recent=recent)


@app.route("/admin/users")
@role_required("super_admin")
def admin_users():
    with get_db() as db:
        users = db.execute(
            """
            SELECT id, username, full_name, email, role, is_active, created_at
            FROM users
            ORDER BY
                CASE role
                    WHEN 'super_admin' THEN 1
                    WHEN 'medical' THEN 2
                    ELSE 3
                END,
                full_name
            """
        ).fetchall()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/new", methods=("GET", "POST"))
@role_required("super_admin")
def admin_create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        if not all([username, full_name, email, password, role]):
            flash("All fields are required.", "danger")
        elif role not in ("medical", "student"):
            flash("Only Medical and Student accounts can be created here.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        else:
            try:
                with get_db() as db:
                    db.execute(
                        """
                        INSERT INTO users
                            (username, password_hash, full_name, email, role)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            username,
                            generate_password_hash(password),
                            full_name,
                            email,
                            role,
                        ),
                    )

                log_activity(
                    g.user["id"], "CREATE_USER",
                    f"Created {role} account: {username}"
                )
                flash("User account created successfully.", "success")
                return redirect(url_for("admin_users"))
            except Exception:
                flash("Username or email already exists.", "danger")

    return render_template(
        "admin/user_form.html",
        user=None,
        form_title="Create User",
    )


@app.route("/admin/users/<int:user_id>/edit", methods=("GET", "POST"))
@role_required("super_admin")
def admin_edit_user(user_id):
    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()

    if user is None:
        abort(404)

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", user["role"])
        password = request.form.get("password", "")

        if not full_name or not email:
            flash("Full name and email are required.", "danger")
        elif role not in ("medical", "student", "super_admin"):
            flash("Invalid role.", "danger")
        elif user["id"] == g.user["id"] and role != "super_admin":
            flash("You cannot remove your own Super Admin role.", "danger")
        elif password and len(password) < 8:
            flash("New password must be at least 8 characters.", "danger")
        else:
            try:
                with get_db() as db:
                    if password:
                        db.execute(
                            """
                            UPDATE users
                            SET full_name = ?, email = ?, role = ?,
                                password_hash = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE id = ?
                            """,
                            (
                                full_name,
                                email,
                                role,
                                generate_password_hash(password),
                                user_id,
                            ),
                        )
                    else:
                        db.execute(
                            """
                            UPDATE users
                            SET full_name = ?, email = ?, role = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = ?
                            """,
                            (full_name, email, role, user_id),
                        )

                log_activity(
                    g.user["id"], "EDIT_USER", f"Updated user id {user_id}"
                )
                flash("User account updated.", "success")
                return redirect(url_for("admin_users"))
            except Exception:
                flash("Email may already be in use.", "danger")

    return render_template(
        "admin/user_form.html",
        user=user,
        form_title="Edit User",
    )


@app.post("/admin/users/<int:user_id>/toggle")
@role_required("super_admin")
def admin_toggle_user(user_id):
    if user_id == g.user["id"]:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("admin_users"))

    with get_db() as db:
        user = db.execute(
            "SELECT id, username, is_active FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if user is None:
            abort(404)

        new_state = 0 if user["is_active"] else 1
        db.execute(
            """
            UPDATE users
            SET is_active = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (new_state, user_id),
        )

    action = "ACTIVATE_USER" if new_state else "DEACTIVATE_USER"
    log_activity(g.user["id"], action, f"User: {user['username']}")
    flash(
        f"User {user['username']} is now "
        f"{'active' if new_state else 'inactive'}.",
        "success",
    )
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/delete")
@role_required("super_admin")
def admin_delete_user(user_id):
    if user_id == g.user["id"]:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("admin_users"))

    try:
        with get_db() as db:
            user = db.execute(
                "SELECT username FROM users WHERE id = ?", (user_id,)
            ).fetchone()

            if user is None:
                abort(404)

            db.execute("DELETE FROM users WHERE id = ?", (user_id,))

        log_activity(
            g.user["id"], "DELETE_USER", f"Deleted user: {user['username']}"
        )
        flash("User account deleted.", "success")
    except Exception:
        flash(
            "This user cannot be permanently deleted because consultation records "
            "reference the account. Deactivate the account instead.",
            "warning",
        )

    return redirect(url_for("admin_users"))


@app.route("/admin/consultations")
@role_required("super_admin")
def admin_consultations():
    status = request.args.get("status", "").strip()

    query = """
        SELECT c.*, s.full_name AS student_name, m.full_name AS medical_name
        FROM consultations c
        JOIN users s ON s.id = c.student_id
        LEFT JOIN users m ON m.id = c.medical_id
    """
    params = []

    if status in CONSULTATION_STATUSES:
        query += " WHERE c.status = ?"
        params.append(status)

    query += " ORDER BY c.created_at DESC"

    with get_db() as db:
        consultations = db.execute(query, params).fetchall()
        medical_staff = db.execute(
            """
            SELECT id, full_name FROM users
            WHERE role = 'medical' AND is_active = 1
            ORDER BY full_name
            """
        ).fetchall()

    return render_template(
        "admin/consultations.html",
        consultations=consultations,
        medical_staff=medical_staff,
        statuses=CONSULTATION_STATUSES,
        selected_status=status,
    )


@app.post("/admin/consultations/<int:consultation_id>/assign")
@role_required("super_admin")
def admin_assign_consultation(consultation_id):
    medical_id = request.form.get("medical_id", "").strip()

    with get_db() as db:
        consultation = db.execute(
            "SELECT id FROM consultations WHERE id = ?", (consultation_id,)
        ).fetchone()

        if consultation is None:
            abort(404)

        if medical_id:
            staff = db.execute(
                """
                SELECT id FROM users
                WHERE id = ? AND role = 'medical' AND is_active = 1
                """,
                (medical_id,),
            ).fetchone()

            if staff is None:
                flash(
                    "Selected medical staff account is invalid or inactive.",
                    "danger",
                )
                return redirect(url_for("admin_consultations"))

            db.execute(
                """
                UPDATE consultations
                SET medical_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (medical_id, consultation_id),
            )
            detail = (
                f"Assigned consultation #{consultation_id} "
                f"to medical user #{medical_id}"
            )
        else:
            db.execute(
                """
                UPDATE consultations
                SET medical_id = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (consultation_id,),
            )
            detail = f"Unassigned consultation #{consultation_id}"

    log_activity(g.user["id"], "ASSIGN_CONSULTATION", detail)
    flash("Consultation assignment updated.", "success")
    return redirect(url_for("admin_consultations"))


@app.post("/admin/consultations/<int:consultation_id>/status")
@role_required("super_admin")
def admin_update_consultation_status(consultation_id):
    status = request.form.get("status", "")

    if status not in CONSULTATION_STATUSES:
        flash("Invalid consultation status.", "danger")
        return redirect(url_for("admin_consultations"))

    with get_db() as db:
        db.execute(
            """
            UPDATE consultations
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, consultation_id),
        )

    log_activity(
        g.user["id"],
        "ADMIN_STATUS_UPDATE",
        f"Consultation #{consultation_id} -> {status}",
    )
    flash("Consultation status updated.", "success")
    return redirect(url_for("admin_consultations"))


@app.route("/admin/reports")
@role_required("super_admin")
def admin_reports():
    with get_db() as db:
        status_counts = db.execute(
            """
            SELECT status, COUNT(*) AS total
            FROM consultations
            GROUP BY status
            ORDER BY total DESC
            """
        ).fetchall()

        medical_load = db.execute(
            """
            SELECT COALESCE(m.full_name, 'Unassigned') AS medical_name,
                   COUNT(c.id) AS total
            FROM consultations c
            LEFT JOIN users m ON m.id = c.medical_id
            GROUP BY c.medical_id
            ORDER BY total DESC
            """
        ).fetchall()

        activity = db.execute(
            """
            SELECT a.*, COALESCE(u.full_name, 'System') AS user_name
            FROM activity_logs a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.created_at DESC
            LIMIT 100
            """
        ).fetchall()

        totals = db.execute(
            """
            SELECT
                COUNT(*) AS all_requests,
                SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
                SUM(CASE WHEN status = 'Cancelled' THEN 1 ELSE 0 END) AS cancelled
            FROM consultations
            """
        ).fetchone()

    return render_template(
        "admin/reports.html",
        status_counts=status_counts,
        medical_load=medical_load,
        activity=activity,
        totals=totals,
    )


# ---------------------------------------------------------------------------
# Medical Staff
# ---------------------------------------------------------------------------

@app.route("/medical")
@role_required("medical")
def medical_dashboard():
    with get_db() as db:
        assigned = db.execute(
            """
            SELECT c.*, s.full_name AS student_name, s.email AS student_email
            FROM consultations c
            JOIN users s ON s.id = c.student_id
            WHERE c.medical_id = ?
            ORDER BY
                CASE c.status
                    WHEN 'Pending' THEN 1
                    WHEN 'Accepted' THEN 2
                    WHEN 'In Progress' THEN 3
                    ELSE 4
                END,
                c.created_at DESC
            """,
            (g.user["id"],),
        ).fetchall()

        counts = db.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = 'In Progress' THEN 1 ELSE 0 END) AS in_progress,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed
            FROM consultations
            WHERE medical_id = ?
            """,
            (g.user["id"],),
        ).fetchone()

    return render_template(
        "medical/dashboard.html",
        assigned=assigned,
        counts=counts,
    )


@app.route("/medical/consultations/<int:consultation_id>", methods=("GET", "POST"))
@role_required("medical")
def medical_consultation(consultation_id):
    consultation = get_consultation_or_404(consultation_id)

    # A Medical staff member may only access requests assigned to them.
    if consultation["medical_id"] != g.user["id"]:
        abort(403)

    if request.method == "POST":
        status = request.form.get("status", "")
        notes = request.form.get("medical_notes", "").strip()

        if status not in CONSULTATION_STATUSES:
            flash("Invalid status.", "danger")
        else:
            with get_db() as db:
                db.execute(
                    """
                    UPDATE consultations
                    SET status = ?, medical_notes = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, notes, consultation_id),
                )

            log_activity(
                g.user["id"],
                "MEDICAL_UPDATE",
                f"Consultation #{consultation_id} -> {status}",
            )
            flash("Consultation updated successfully.", "success")
            return redirect(
                url_for(
                    "medical_consultation",
                    consultation_id=consultation_id,
                )
            )

        consultation = get_consultation_or_404(consultation_id)

    return render_template(
        "medical/consultation.html",
        consultation=consultation,
        statuses=CONSULTATION_STATUSES,
    )


@app.route("/medical/history")
@role_required("medical")
def medical_history():
    with get_db() as db:
        history = db.execute(
            """
            SELECT c.*, s.full_name AS student_name
            FROM consultations c
            JOIN users s ON s.id = c.student_id
            WHERE c.medical_id = ?
            ORDER BY c.updated_at DESC
            """,
            (g.user["id"],),
        ).fetchall()

    return render_template("medical/history.html", history=history)


# ---------------------------------------------------------------------------
# Student
# ---------------------------------------------------------------------------

@app.route("/student")
@role_required("student")
def student_dashboard():
    with get_db() as db:
        consultations = db.execute(
            """
            SELECT c.*, m.full_name AS medical_name
            FROM consultations c
            LEFT JOIN users m ON m.id = c.medical_id
            WHERE c.student_id = ?
            ORDER BY c.created_at DESC
            """,
            (g.user["id"],),
        ).fetchall()

        counts = db.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed
            FROM consultations
            WHERE student_id = ?
            """,
            (g.user["id"],),
        ).fetchone()

    return render_template(
        "student/dashboard.html",
        consultations=consultations,
        counts=counts,
    )


@app.route("/student/consultations/new", methods=("GET", "POST"))
@role_required("student")
def student_new_consultation():
    if request.method == "POST":
        concern = request.form.get("concern", "").strip()
        preferred_date = request.form.get("preferred_date", "").strip()
        preferred_time = request.form.get("preferred_time", "").strip()
        student_notes = request.form.get("student_notes", "").strip()

        if not concern:
            flash("Please describe your concern.", "danger")
        elif len(concern) < 10:
            flash("Please provide a little more detail about your concern.", "danger")
        else:
            with get_db() as db:
                consultation_id = db.execute(
                    """
                    INSERT INTO consultations
                        (student_id, concern, preferred_date,
                         preferred_time, student_notes)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        g.user["id"],
                        concern,
                        preferred_date or None,
                        preferred_time or None,
                        student_notes or None,
                    ),
                ).lastrowid

            log_activity(
                g.user["id"],
                "CREATE_CONSULTATION",
                f"Created consultation #{consultation_id}",
            )
            flash("Consultation request submitted successfully.", "success")
            return redirect(url_for("student_dashboard"))

    return render_template("student/new_consultation.html")


@app.route("/student/consultations/<int:consultation_id>")
@role_required("student")
def student_consultation(consultation_id):
    consultation = get_consultation_or_404(consultation_id)

    # Students can only view their own requests.
    if consultation["student_id"] != g.user["id"]:
        abort(403)

    return render_template(
        "student/consultation.html",
        consultation=consultation,
    )


@app.errorhandler(403)
def forbidden(_error):
    return (
        render_template(
            "error.html",
            code=403,
            message="You do not have permission to access this page.",
        ),
        403,
    )


@app.errorhandler(404)
def not_found(_error):
    return (
        render_template(
            "error.html",
            code=404,
            message="The requested page was not found.",
        ),
        404,
    )


if __name__ == "__main__":
    # Debug mode is convenient for local development. Disable it in production.
    app.run(debug=True, host="127.0.0.1", port=5000)
