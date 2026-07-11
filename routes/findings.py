from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from datetime import datetime

from models import db, SecurityFinding, User

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
def update_finding(finding_id):
    finding = SecurityFinding.query.get_or_404(finding_id)
    
    status = request.form.get("status")
    assigned_user_id = request.form.get("assigned_user_id")
    due_date_raw = request.form.get("due_date")
    remediation_note = request.form.get("remediation_note")
    
    if status in ["open", "resolved", "accepted_risk", "false_positive"]:
        finding.status = status
        
    if assigned_user_id:
        if assigned_user_id == "none":
            finding.assigned_user_id = None
        else:
            finding.assigned_user_id = int(assigned_user_id)
            
    if due_date_raw:
        try:
            finding.due_date = datetime.strptime(due_date_raw, "%Y-%m-%d")
        except ValueError:
            pass
    elif due_date_raw == "":
        finding.due_date = None
        
    if remediation_note is not None:
        finding.remediation_note = remediation_note.strip()
        
    db.session.commit()
    flash("Finding details updated successfully.", "success")
    return redirect(url_for("findings.list_findings", status=finding.status))

@findings_bp.route("/findings/<int:finding_id>/delete", methods=["POST"])
@login_required
def delete_finding(finding_id):
    if not current_user.is_admin:
        flash("Unauthorised access.", "error")
        return redirect(url_for("findings.list_findings"))
    finding = SecurityFinding.query.get_or_404(finding_id)
    db.session.delete(finding)
    db.session.commit()
    flash("Finding deleted successfully.", "success")
    return redirect(url_for("findings.list_findings"))
