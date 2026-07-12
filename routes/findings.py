from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from datetime import datetime, timezone

from models import db, SecurityFinding, User
from routes.admin import admin_required

findings_bp = Blueprint("findings", __name__)

@findings_bp.route("/findings")
@login_required
def list_findings():
    status = request.args.get("status", "open").strip()
    severity = request.args.get("severity", "").strip()
    search = request.args.get("search", "").strip()
    
    query = SecurityFinding.query
    
    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)
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

    # not_observed is system-managed — not allowed as a manual status
    valid_statuses = ["open", "resolved", "accepted_risk", "false_positive", "needs_review"]
    if status not in valid_statuses:
        flash("Invalid status selected.", "error")
        return redirect(url_for("findings.list_findings", status=finding.status))
    finding.status = status

    # Validate assigned user exists
    if assigned_user_id:
        if assigned_user_id == "none":
            finding.assigned_user_id = None
        else:
            try:
                uid = int(assigned_user_id)
                assigned_user = db.session.get(User, uid)
                if not assigned_user:
                    flash("Selected user could not be found.", "error")
                    return redirect(url_for("findings.list_findings", status=finding.status))
                finding.assigned_user_id = uid
            except ValueError:
                flash("Invalid user selection.", "error")
                return redirect(url_for("findings.list_findings", status=finding.status))

    if due_date_raw:
        try:
            finding.due_date = datetime.strptime(due_date_raw, "%Y-%m-%d")
        except ValueError:
            flash("Invalid due date format.", "error")
            return redirect(url_for("findings.list_findings", status=finding.status))
    else:
        finding.due_date = None

    if remediation_note is not None:
        finding.remediation_note = remediation_note.strip()

    # Handle acceptance_expiry — only meaningful when status is accepted_risk
    if status == "accepted_risk":
        if acceptance_expiry_raw:
            try:
                finding.acceptance_expiry = datetime.strptime(acceptance_expiry_raw, "%Y-%m-%d")
            except ValueError:
                flash("Invalid acceptance expiry date format.", "error")
                return redirect(url_for("findings.list_findings", status=finding.status))
        else:
            finding.acceptance_expiry = None  # Indefinite acceptance
    else:
        # Clear expiry when no longer in accepted_risk state
        finding.acceptance_expiry = None

    db.session.commit()
    flash("Finding details updated successfully.", "success")
    return redirect(url_for("findings.list_findings", status=finding.status))

@findings_bp.route("/findings/<int:finding_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_finding(finding_id):
    finding = SecurityFinding.query.get_or_404(finding_id)
    db.session.delete(finding)
    db.session.commit()
    flash("Finding deleted successfully.", "success")
    return redirect(url_for("findings.list_findings"))
