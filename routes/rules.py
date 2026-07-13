from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from functools import wraps

from models import db, SecurityRule, User
from services.rule_service import seed_default_rules, validate_rule_conditions

rules_bp = Blueprint("rules", __name__)


# Handle the admin required operation.
def admin_required(f):
    """Decorator that requires the current user to be an admin."""
    # Handle the decorated operation.
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        # Handle the branch where not current_user.is_admin evaluates to true.
        if not current_user.is_admin:
            flash("Access denied. Only administrators can manage security rules.", "error")
            return redirect(url_for("rules.list_rules"))
        return f(*args, **kwargs)
    return decorated


# List rules.
@rules_bp.route("/rules", methods=["GET"])
@login_required
def list_rules():
    # Seed default rules for admin if not yet present
    admin_user = User.query.filter_by(is_admin=True).first()
    # Handle the branch where admin_user evaluates to true.
    if admin_user:
        seed_default_rules(admin_user.id)
    # Show all rules (global/admin-managed Model A)
    rules = SecurityRule.query.order_by(SecurityRule.created_at.desc()).all()
    return render_template("rules.html", rules=rules)


# Add rule.
@rules_bp.route("/rules/add", methods=["POST"])
@admin_required
def add_rule():
    name = request.form.get("name", "").strip()
    severity = request.form.get("severity", "Medium").strip()
    scope = request.form.get("scope", "*").strip()
    port_service_condition = request.form.get("port_service_condition", "").strip()
    asset_criticality_condition = request.form.get("asset_criticality_condition", "*").strip()
    exception_list = request.form.get("exception_list", "").strip()
    remediation_text = request.form.get("remediation_text", "").strip()
    enabled = request.form.get("enabled") == "y"

    # Handle the branch where not name or not port_service_condition evaluates to true.
    if not name or not port_service_condition:
        flash("Please fill in rule name and matching conditions.", "error")
        return redirect(url_for("rules.list_rules"))

    ok, err = validate_rule_conditions(port_service_condition, scope, severity, asset_criticality_condition)
    # Handle the branch where not ok evaluates to true.
    if not ok:
        flash(f"Rule validation failed: {err}", "error")
        return redirect(url_for("rules.list_rules"))

    admin_user = User.query.filter_by(is_admin=True).first()
    rule = SecurityRule(
        user_id=admin_user.id,
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


# Handle the edit rule operation.
@rules_bp.route("/rules/<int:rule_id>/edit", methods=["POST"])
@admin_required
def edit_rule(rule_id):
    rule = SecurityRule.query.get_or_404(rule_id)

    new_condition = request.form.get("port_service_condition", "").strip()
    new_scope = request.form.get("scope", "*").strip()
    new_severity = request.form.get("severity", "Medium").strip()
    new_criticality = request.form.get("asset_criticality_condition", "*").strip()

    ok, err = validate_rule_conditions(new_condition, new_scope, new_severity, new_criticality)
    # Handle the branch where not ok evaluates to true.
    if not ok:
        flash(f"Rule validation failed: {err}", "error")
        return redirect(url_for("rules.list_rules"))

    rule.name = request.form.get("name", "").strip()
    rule.severity = new_severity
    rule.scope = new_scope
    rule.port_service_condition = new_condition
    rule.asset_criticality_condition = new_criticality
    rule.exception_list = request.form.get("exception_list", "").strip()
    rule.remediation_text = request.form.get("remediation_text", "").strip()
    rule.enabled = request.form.get("enabled") == "y"

    db.session.commit()
    flash("Security rule successfully updated.", "success")
    return redirect(url_for("rules.list_rules"))


# Handle the toggle rule operation.
@rules_bp.route("/rules/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    rule = SecurityRule.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    status_str = "enabled" if rule.enabled else "disabled"
    flash(f"Security rule '{rule.name}' has been {status_str}.", "success")
    return redirect(url_for("rules.list_rules"))


# Delete rule.
@rules_bp.route("/rules/<int:rule_id>/delete", methods=["POST"])
@admin_required
def delete_rule(rule_id):
    rule = SecurityRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    flash("Security rule successfully deleted.", "success")
    return redirect(url_for("rules.list_rules"))
