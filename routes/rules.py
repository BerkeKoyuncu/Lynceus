from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from models import db, SecurityRule
from services.rule_service import seed_default_rules

rules_bp = Blueprint("rules", __name__)

@rules_bp.route("/rules", methods=["GET"])
@login_required
def list_rules():
    # Ensure default rules are seeded for user
    seed_default_rules(current_user.id)
    rules = SecurityRule.query.filter_by(user_id=current_user.id).order_by(SecurityRule.created_at.desc()).all()
    return render_template("rules.html", rules=rules)

@rules_bp.route("/rules/add", methods=["POST"])
@login_required
def add_rule():
    name = request.form.get("name", "").strip()
    severity = request.form.get("severity", "Medium").strip()
    scope = request.form.get("scope", "*").strip()
    port_service_condition = request.form.get("port_service_condition", "").strip()
    asset_criticality_condition = request.form.get("asset_criticality_condition", "*").strip()
    exception_list = request.form.get("exception_list", "").strip()
    remediation_text = request.form.get("remediation_text", "").strip()
    enabled = request.form.get("enabled") == "y"

    if not name or not port_service_condition:
        flash("Please fill in rule name and matching conditions.", "error")
        return redirect(url_for("rules.list_rules"))

    rule = SecurityRule(
        user_id=current_user.id,
        name=name,
        severity=severity,
        scope=scope,
        port_service_condition=port_service_condition,
        asset_criticality_condition=asset_criticality_condition,
        exception_list=exception_list,
        remediation_text=remediation_text,
        enabled=enabled
    )
    db.session.add(rule)
    db.session.commit()
    flash("Security rule successfully added.", "success")
    return redirect(url_for("rules.list_rules"))

@rules_bp.route("/rules/<int:rule_id>/edit", methods=["POST"])
@login_required
def edit_rule(rule_id):
    rule = SecurityRule.query.filter_by(id=rule_id, user_id=current_user.id).first_or_404()
    
    rule.name = request.form.get("name", "").strip()
    rule.severity = request.form.get("severity", "Medium").strip()
    rule.scope = request.form.get("scope", "*").strip()
    rule.port_service_condition = request.form.get("port_service_condition", "").strip()
    rule.asset_criticality_condition = request.form.get("asset_criticality_condition", "*").strip()
    rule.exception_list = request.form.get("exception_list", "").strip()
    rule.remediation_text = request.form.get("remediation_text", "").strip()
    rule.enabled = request.form.get("enabled") == "y"

    db.session.commit()
    flash("Security rule successfully updated.", "success")
    return redirect(url_for("rules.list_rules"))

@rules_bp.route("/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def toggle_rule(rule_id):
    rule = SecurityRule.query.filter_by(id=rule_id, user_id=current_user.id).first_or_404()
    rule.enabled = not rule.enabled
    db.session.commit()
    status_str = "enabled" if rule.enabled else "disabled"
    flash(f"Security rule '{rule.name}' has been {status_str}.", "success")
    return redirect(url_for("rules.list_rules"))

@rules_bp.route("/rules/<int:rule_id>/delete", methods=["POST"])
@login_required
def delete_rule(rule_id):
    rule = SecurityRule.query.filter_by(id=rule_id, user_id=current_user.id).first_or_404()
    db.session.delete(rule)
    db.session.commit()
    flash("Security rule successfully deleted.", "success")
    return redirect(url_for("rules.list_rules"))
