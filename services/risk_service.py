from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from models import Asset, HoneypotLog, SecurityAnomaly, SecurityFinding, SystemSetting, User, db


FINDING_WEIGHTS = {
    "Critical": 50,
    "High": 30,
    "Medium": 12,
    "Low": 3,
}
FINDING_STATUS_MULTIPLIERS = {
    "open": 1.0,
    "needs_review": 0.4,
}
ANOMALY_WEIGHTS = {
    "High": 25,
    "Medium": 15,
    "Low": 5,
}
CRITICALITY_MULTIPLIERS = {
    "Critical": 1.15,
    "High": 1.08,
    "Medium": 1.0,
    "Low": 0.9,
}


def _normalise_label(value, allowed, fallback):
    value = (value or fallback).strip().lower()
    return next((label for label in allowed if label.lower() == value), fallback)


def _asset_level(score):
    if score >= 75:
        return "Critical", "var(--error-text)", "var(--error-bg)"
    if score >= 40:
        return "High", "var(--error-text)", "var(--error-bg)"
    if score >= 15:
        return "Medium", "var(--warning-text)", "var(--warning-bg)"
    return "Low", "var(--success-text)", "var(--success-bg)"


def _score_evidence(criticality, is_trusted, findings, anomalies):
    finding_points = 0.0
    for finding in findings:
        severity = _normalise_label(finding.severity, FINDING_WEIGHTS, "Medium")
        status_multiplier = FINDING_STATUS_MULTIPLIERS.get(finding.status, 0)
        finding_points += FINDING_WEIGHTS[severity] * status_multiplier
    finding_points = min(round(finding_points), 80)

    anomaly_points = 0
    has_rogue_device = False
    for anomaly in anomalies:
        confidence = _normalise_label(anomaly.confidence_score, ANOMALY_WEIGHTS, "High")
        anomaly_points += ANOMALY_WEIGHTS[confidence]
        has_rogue_device = has_rogue_device or anomaly.anomaly_type == "rogue_device"
    anomaly_points = min(anomaly_points, 30)

    # A rogue-device anomaly already represents the trust problem, so do not
    # charge the same signal a second time as an inventory trust penalty.
    trust_points = 8 if not is_trusted and not has_rogue_device else 0
    base_score = min(finding_points + anomaly_points + trust_points, 100)
    criticality_label = _normalise_label(
        criticality,
        CRITICALITY_MULTIPLIERS,
        "Medium",
    )
    multiplier = CRITICALITY_MULTIPLIERS[criticality_label]
    score = min(int((base_score * multiplier) + 0.5), 100)

    return {
        "score": score,
        "finding_score": finding_points,
        "anomaly_score": anomaly_points,
        "trust_score": trust_points,
        "criticality_multiplier": multiplier,
    }


def _matching_asset_findings(asset):
    return SecurityFinding.query.filter(
        SecurityFinding.status.in_(tuple(FINDING_STATUS_MULTIPLIERS)),
        db.or_(
            SecurityFinding.asset_id == asset.id,
            db.and_(
                SecurityFinding.asset_id.is_(None),
                SecurityFinding.ip_address == asset.ip_address,
            ),
        ),
    ).all()


def _matching_asset_anomalies(asset):
    match_conditions = [SecurityAnomaly.ip_address == asset.ip_address]
    if asset.mac_address:
        match_conditions.append(
            func.lower(SecurityAnomaly.mac_address) == asset.mac_address.strip().lower()
        )
    return SecurityAnomaly.query.filter(
        SecurityAnomaly.is_resolved == False,
        db.or_(*match_conditions),
    ).all()


def calculate_asset_risk(asset, findings=None, anomalies=None):
    """Calculate an evidence-based risk score for one inventory asset."""
    if findings is None:
        findings = _matching_asset_findings(asset)
    if anomalies is None:
        anomalies = _matching_asset_anomalies(asset)

    scoring = _score_evidence(
        criticality=asset.criticality,
        is_trusted=asset.is_trusted,
        findings=findings,
        anomalies=anomalies,
    )
    level, color, bg = _asset_level(scoring["score"])

    return {
        "id": asset.id,
        "name": asset.name or asset.ip_address,
        "ip_address": asset.ip_address,
        "mac_address": asset.mac_address or "N/A",
        "criticality": asset.criticality or "Medium",
        "is_trusted": asset.is_trusted,
        "level": level,
        "color": color,
        "bg": bg,
        **scoring,
    }


def _network_level(score):
    if score >= 70:
        return "High", "var(--error-text)", "var(--error-bg)"
    if score >= 35:
        return "Medium", "var(--warning-text)", "var(--warning-bg)"
    return "Low", "var(--success-text)", "var(--success-bg)"


def _finding_factor_messages(findings):
    factors = []
    confirmed = defaultdict(int)
    needs_review = defaultdict(int)
    for finding in findings:
        severity = _normalise_label(finding.severity, FINDING_WEIGHTS, "Medium")
        target = confirmed if finding.status == "open" else needs_review
        target[severity] += 1

    for severity in ("Critical", "High", "Medium", "Low"):
        if confirmed[severity]:
            factors.append({
                "severity": "high" if severity in {"Critical", "High"} else severity.lower(),
                "message": f"{confirmed[severity]} open {severity} security finding(s) detected.",
            })
    review_count = sum(needs_review.values())
    if review_count:
        factors.append({
            "severity": "medium",
            "message": f"{review_count} potential finding(s) still need review.",
        })
    return factors


def calculate_network_risk_score(user_id=None):
    """
    Derive network risk from shared asset scores, then add small operational
    coverage and recent intrusion components. The score is global inventory
    risk; ``user_id`` only selects the viewer's notification configuration.
    """
    assets = Asset.query.all()
    findings = SecurityFinding.query.filter(
        SecurityFinding.status.in_(tuple(FINDING_STATUS_MULTIPLIERS))
    ).all()
    anomalies = SecurityAnomaly.query.filter_by(is_resolved=False).all()

    findings_by_asset = defaultdict(list)
    orphan_findings_by_ip = defaultdict(list)
    for finding in findings:
        if finding.asset_id is not None:
            findings_by_asset[finding.asset_id].append(finding)
        else:
            orphan_findings_by_ip[finding.ip_address].append(finding)

    asset_risks = []
    matched_finding_ids = set()
    matched_anomaly_ids = set()
    for asset in assets:
        asset_findings = list(findings_by_asset.get(asset.id, []))
        asset_findings.extend(orphan_findings_by_ip.get(asset.ip_address, []))
        matched_finding_ids.update(finding.id for finding in asset_findings)

        asset_mac = asset.mac_address.strip().lower() if asset.mac_address else None
        asset_anomalies = []
        for anomaly in anomalies:
            anomaly_mac = anomaly.mac_address.strip().lower() if anomaly.mac_address else None
            if anomaly.ip_address == asset.ip_address or (asset_mac and anomaly_mac == asset_mac):
                asset_anomalies.append(anomaly)
                matched_anomaly_ids.add(anomaly.id)

        asset_risks.append(calculate_asset_risk(asset, asset_findings, asset_anomalies))

    # Preserve visibility of findings/anomalies that pre-date asset inventory
    # linkage by treating each unmatched IP as a medium-criticality evidence group.
    orphan_evidence = defaultdict(lambda: {"findings": [], "anomalies": []})
    for finding in findings:
        if finding.id not in matched_finding_ids:
            orphan_evidence[finding.ip_address]["findings"].append(finding)
    for anomaly in anomalies:
        if anomaly.id not in matched_anomaly_ids:
            orphan_evidence[anomaly.ip_address]["anomalies"].append(anomaly)

    evidence_scores = [risk["score"] for risk in asset_risks if risk["score"] > 0]
    for evidence in orphan_evidence.values():
        orphan_score = _score_evidence(
            criticality="Medium",
            is_trusted=True,
            findings=evidence["findings"],
            anomalies=evidence["anomalies"],
        )["score"]
        if orphan_score:
            evidence_scores.append(orphan_score)

    if evidence_scores:
        ordered_scores = sorted(evidence_scores, reverse=True)
        top_scores = ordered_scores[:5]
        evidence_score = round((ordered_scores[0] * 0.7) + ((sum(top_scores) / len(top_scores)) * 0.3))
        breadth_bonus = min(max(len(ordered_scores) - 1, 0) * 2, 10)
    else:
        evidence_score = 0
        breadth_bonus = 0

    risk_factors = _finding_factor_messages(findings)

    anomaly_counts = defaultdict(int)
    for anomaly in anomalies:
        confidence = _normalise_label(anomaly.confidence_score, ANOMALY_WEIGHTS, "High")
        anomaly_counts[confidence] += 1
    for confidence in ("High", "Medium", "Low"):
        if anomaly_counts[confidence]:
            risk_factors.append({
                "severity": "high" if confidence == "High" else confidence.lower(),
                "message": f"{anomaly_counts[confidence]} unresolved {confidence}-confidence anomaly/anomalies detected.",
            })

    untrusted_count = sum(1 for asset in assets if not asset.is_trusted)
    if untrusted_count:
        risk_factors.append({
            "severity": "medium",
            "message": f"{untrusted_count} inventory asset(s) are marked as Untrusted.",
        })

    operational_penalty = 0
    admin_user = User.query.filter_by(is_admin=True).first()
    admin_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first() if admin_user else None
    if not admin_setting or not admin_setting.honeypot_active:
        operational_penalty += 5
        risk_factors.append({
            "severity": "low",
            "message": "Honeypot is disabled, reducing intrusion-detection coverage.",
        })

    user_setting = SystemSetting.query.filter_by(user_id=user_id).first() if user_id else None
    if not user_setting or not (
        user_setting.smtp_server
        and user_setting.smtp_sender
        and user_setting.alert_recipient
    ):
        operational_penalty += 3
        risk_factors.append({
            "severity": "low",
            "message": "Email notifications are not fully configured for this user.",
        })

    one_day_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    recent_source_count = db.session.query(HoneypotLog.ip_address).filter(
        HoneypotLog.created_at >= one_day_ago
    ).distinct().count()
    intrusion_score = min(recent_source_count * 2, 8)
    if recent_source_count:
        risk_factors.append({
            "severity": "medium",
            "message": f"{recent_source_count} unique source(s) hit honeypot endpoints in the last 24 hours.",
        })

    score = min(evidence_score + breadth_bonus + operational_penalty + intrusion_score, 100)
    level, color, bg = _network_level(score)
    asset_risks.sort(key=lambda risk: risk["score"], reverse=True)

    return {
        "score": score,
        "level": level,
        "color": color,
        "bg": bg,
        "factors": risk_factors,
        "assets": asset_risks,
        "components": {
            "evidence": evidence_score,
            "breadth": breadth_bonus,
            "operational": operational_penalty,
            "intrusions": intrusion_score,
        },
    }
