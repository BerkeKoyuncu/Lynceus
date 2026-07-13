from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from datetime import datetime

from models import db, SecurityFinding, User
from routes.admin import admin_required

findings_bp = Blueprint("findings", __name__)

# List findings.
@findings_bp.route("/findings")
@login_required
def list_findings():
    status = request.args.get("status", "open").strip()
    severity = request.args.get("severity", "").strip()
    search = request.args.get("search", "").strip()
    
    query = SecurityFinding.query
    
    # Handle the branch where status evaluates to true.
    if status:
        query = query.filter_by(status=status)
    # Handle the branch where severity evaluates to true.
    if severity:
        query = query.filter_by(severity=severity)
    # Handle the branch where search evaluates to true.
    if search:
        query = query.filter(
            db.or_(
                SecurityFinding.ip_address.ilike(f"%{search}%"),
                SecurityFinding.cve.ilike(f"%{search}%"),
                SecurityFinding.service.ilike(f"%{search}%"),
                SecurityFinding.evidence.ilike(f"%{search}%")
            )
        )
        
    findings = query.order_by(SecurityFinding.last_seen.desc()).all()
    users = User.query.all()
    
    return render_template(
        "findings.html",
        findings=findings,
        users=users,
        selected_status=status,
        selected_severity=severity,
        search=search
    )

# Update finding.
@findings_bp.route("/findings/<int:finding_id>/update", methods=["POST"])
@login_required
@admin_required
def update_finding(finding_id):
    finding = SecurityFinding.query.get_or_404(finding_id)

    status = request.form.get("status")
    assigned_user_id = request.form.get("assigned_user_id")
    due_date_raw = request.form.get("due_date", "").strip()
    remediation_note = request.form.get("remediation_note")
    acceptance_expiry_raw = request.form.get("acceptance_expiry", "").strip()

    # Handle the branch where status is not None evaluates to true.
    if status is not None:
        valid_statuses = ["open", "resolved", "accepted_risk", "false_positive", "needs_review"]
        # Handle the branch where status not in valid_statuses evaluates to true.
        if status not in valid_statuses:
            flash("Invalid status selected.", "error")
            return redirect(url_for("findings.list_findings", status=finding.status))
        finding.status = status

    # Validate assigned user exists
    if assigned_user_id:
        # Handle the branch where assigned_user_id == 'none' evaluates to true.
        if assigned_user_id == "none":
            finding.assigned_user_id = None
        # Handle the fallback branch when the preceding condition does not match.
        else:
            # Run this block with structured exception handling.
            try:
                uid = int(assigned_user_id)
                assigned_user = db.session.get(User, uid)
                # Handle the branch where not assigned_user evaluates to true.
                if not assigned_user:
                    flash("Selected user could not be found.", "error")
                    return redirect(url_for("findings.list_findings", status=finding.status))
                finding.assigned_user_id = uid
            # Handle an exception raised by the preceding protected block.
            except ValueError:
                flash("Invalid user selection.", "error")
                return redirect(url_for("findings.list_findings", status=finding.status))

    # Handle the branch where due_date_raw evaluates to true.
    if due_date_raw:
        # Run this block with structured exception handling.
        try:
            finding.due_date = datetime.strptime(due_date_raw, "%Y-%m-%d")
        # Handle an exception raised by the preceding protected block.
        except ValueError:
            flash("Invalid due date format.", "error")
            return redirect(url_for("findings.list_findings", status=finding.status))
    # Handle the fallback branch when the preceding condition does not match.
    else:
        finding.due_date = None

    # Handle the branch where remediation_note is not None evaluates to true.
    if remediation_note is not None:
        finding.remediation_note = remediation_note.strip()

    # Handle acceptance_expiry — only meaningful when status is accepted_risk
    if finding.status == "accepted_risk":
        # Handle the branch where acceptance_expiry_raw evaluates to true.
        if acceptance_expiry_raw:
            # Run this block with structured exception handling.
            try:
                finding.acceptance_expiry = datetime.strptime(acceptance_expiry_raw, "%Y-%m-%d")
            # Handle an exception raised by the preceding protected block.
            except ValueError:
                flash("Invalid acceptance expiry date format.", "error")
                return redirect(url_for("findings.list_findings", status=finding.status))
        # Handle the fallback branch when the preceding condition does not match.
        else:
            finding.acceptance_expiry = None  # Indefinite acceptance
    # Handle the fallback branch when the preceding condition does not match.
    else:
        # Clear expiry when no longer in accepted_risk state
        finding.acceptance_expiry = None

    db.session.commit()
    flash("Finding details updated successfully.", "success")
    return redirect(url_for("findings.list_findings", status=finding.status))

# Delete finding.
@findings_bp.route("/findings/<int:finding_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_finding(finding_id):
    finding = SecurityFinding.query.get_or_404(finding_id)
    db.session.delete(finding)
    db.session.commit()
    flash("Finding deleted successfully.", "success")
    return redirect(url_for("findings.list_findings"))
