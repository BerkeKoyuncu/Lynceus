from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, Response
from flask_login import login_required, current_user
from datetime import datetime, timezone, timedelta
import os
import re
import json
import csv
import io

from models import db, User, ScanResult, ScanSchedule, SystemSetting, ScanCredential
from scanner import calculate_network, validate_scan_target

scan_bp = Blueprint("scan", __name__)

# Run this block with structured exception handling.
try:
    from zoneinfo import ZoneInfo
    APP_TIMEZONE = ZoneInfo("Europe/Istanbul")
# Handle an exception raised by the preceding protected block.
except Exception:
    APP_TIMEZONE = timezone(timedelta(hours=3), "TRT")

SCAN_TYPE_NAMES = {
    "fast": "Fast Port Scan (TCP)",
    "service_version": "Service & Version Scan (TCP)",
    "ping_sweep": "Host Discovery (Ping Sweep)",
    "syn": "TCP SYN Scan (Half-Open)",
    "connect": "TCP Connect Scan (Full Handshake)",
    "udp": "UDP Port Scan",
    "aggressive": "Aggressive Scan",
    "vuln": "Vulnerability Scan (NSE)",
    "quick": "Quick Scan (Legacy)",
    "detailed": "Detailed Scan (Legacy)"
}

# Handle the format local datetime operation.
def format_local_datetime(value):
    # Handle the branch where not value evaluates to true.
    if not value:
        return ""
    # Handle the branch where value.tzinfo is None evaluates to true.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    local_value = value.astimezone(APP_TIMEZONE)
    return local_value.strftime("%Y-%m-%d %H:%M:%S")

# Handle the localtime filter operation.
@scan_bp.app_template_filter("localtime")
def localtime_filter(value):
    return format_local_datetime(value)

# Handle the scan name filter operation.
@scan_bp.app_template_filter("scan_name")
def scan_name_filter(value):
    return SCAN_TYPE_NAMES.get(value, value.capitalize() if value else "")

# Handle the user can view scan operation.
def user_can_view_scan(scan_result):
    return scan_result.user_id == current_user.id or current_user.is_admin

# Determine whether in freeze window.
def is_in_freeze_window(start_str, end_str):
    # Run this block with structured exception handling.
    try:
        start_time = datetime.strptime(start_str.strip(), "%H:%M").time()
        end_time = datetime.strptime(end_str.strip(), "%H:%M").time()
        now_local = datetime.now(APP_TIMEZONE).time()
        # Handle the branch where start_time <= end_time evaluates to true.
        if start_time <= end_time:
            return start_time <= now_local <= end_time
        # Handle the fallback branch when the preceding condition does not match.
        else:
            return now_local >= start_time or now_local <= end_time
    # Handle an exception raised by the preceding protected block.
    except Exception:
        return False

# Determine whether scan frozen.
def is_scan_frozen():
    # Run this block with structured exception handling.
    try:
        admin_user = User.query.filter_by(is_admin=True).first()
        # Handle the branch where not admin_user evaluates to true.
        if not admin_user:
            return False
        admin_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first()
        # Handle the branch where not admin_setting or not admin_setting.scan_freeze_active evaluates to true.
        if not admin_setting or not admin_setting.scan_freeze_active:
            return False
        return is_in_freeze_window(admin_setting.scan_freeze_start, admin_setting.scan_freeze_end)
    # Handle an exception raised by the preceding protected block.
    except Exception:
        return False


# Handle the user available for new scan operation.
def _user_available_for_new_scan(user_id):
    user = User.query.filter(User.id == user_id).first()
    return user if user is not None and not user.is_deleting else None

# Validate scan request.
def validate_scan_request(
    ip_address,
    subnet_mask,
    scan_type,
    ports,
    timing_template,
    credential_ids,
    user_id,
    exclude_targets=None,
    frequency=None
):
    valid_scan_types = [
        "quick", "detailed",
        "fast", "service_version", "ping_sweep",
        "syn", "connect", "udp", "aggressive", "vuln"
    ]
    # Handle the branch where not scan_type or scan_type not in valid_scan_types evaluates to true.
    if not scan_type or scan_type not in valid_scan_types:
        return {"success": False, "error": "Invalid scan type selected."}

    # Handle the branch where frequency is not None evaluates to true.
    if frequency is not None:
        valid_frequencies = ["hourly", "daily", "weekly", "monthly"]
        # Handle the branch where frequency not in valid_frequencies evaluates to true.
        if frequency not in valid_frequencies:
            return {"success": False, "error": "Invalid schedule frequency."}

    # Handle the branch where timing_template not in ['0', '1', '2', '3', '4', '5'] evaluates to true.
    if timing_template not in ["0", "1", "2", "3", "4", "5"]:
        return {"success": False, "error": "Timing template must be between 0 and 5."}

    # Handle the branch where ports evaluates to true.
    if ports:
        # Handle the branch where not re.match('^[0-9,-]+$', ports) evaluates to true.
        if not re.match(r"^[0-9,-]+$", ports):
            return {"success": False, "error": "Invalid ports format. Use numbers, commas, and hyphens (e.g., 22,80,443 or 1-1000)."}
        
        port_list = []
        # Iterate over ports.split(',') and bind each item to part.
        for part in ports.split(","):
            # Handle the branch where '-' in part evaluates to true.
            if "-" in part:
                subparts = part.split("-")
                # Handle the branch where len(subparts) != 2 evaluates to true.
                if len(subparts) != 2:
                    return {"success": False, "error": "Invalid port range format."}
                # Run this block with structured exception handling.
                try:
                    start_port = int(subparts[0])
                    end_port = int(subparts[1])
                    # Handle the branch where start_port > end_port evaluates to true.
                    if start_port > end_port:
                        return {"success": False, "error": f"Invalid port range: {start_port}-{end_port}."}
                    port_list.extend(range(start_port, end_port + 1))
                # Handle an exception raised by the preceding protected block.
                except ValueError:
                    return {"success": False, "error": "Port numbers must be integers."}
            # Handle the fallback branch when the preceding condition does not match.
            else:
                # Run this block with structured exception handling.
                try:
                    port_list.append(int(part))
                # Handle an exception raised by the preceding protected block.
                except ValueError:
                    return {"success": False, "error": "Port numbers must be integers."}
        # Iterate over port_list and bind each item to p.
        for p in port_list:
            # Handle the branch where p < 1 or p > 65535 evaluates to true.
            if p < 1 or p > 65535:
                return {"success": False, "error": f"Port {p} out of range. Ports must be between 1 and 65535."}

    # Handle the branch where credential_ids evaluates to true.
    if credential_ids:
        # Handle the branch where isinstance(credential_ids, str) evaluates to true.
        if isinstance(credential_ids, str):
            cred_id_list = [c.strip() for c in credential_ids.split(",") if c.strip()]
        # Handle the fallback branch when the preceding condition does not match.
        else:
            cred_id_list = [str(c).strip() for c in credential_ids if str(c).strip()]
        
        # Handle the branch where cred_id_list evaluates to true.
        if cred_id_list:
            # Run this block with structured exception handling.
            try:
                int_cred_ids = [int(cid) for cid in cred_id_list]
                user_creds = ScanCredential.query.filter(ScanCredential.id.in_(int_cred_ids)).all()
                # Handle the branch where len(user_creds) != len(int_cred_ids) or any((c.user_id != user_id for c in user_creds)) evaluates to true.
                if len(user_creds) != len(int_cred_ids) or any(c.user_id != user_id for c in user_creds):
                    return {"success": False, "error": "One or more selected credentials are invalid or do not belong to you."}
            # Handle an exception raised by the preceding protected block.
            except ValueError:
                return {"success": False, "error": "Invalid credential IDs format."}

    network_info = calculate_network(ip_address, subnet_mask if subnet_mask else None)
    # Handle the branch where not network_info['success'] evaluates to true.
    if not network_info["success"]:
        return {"success": False, "error": f"Invalid scan target: {network_info['error']}"}

    target_validation = validate_scan_target(network_info, scan_type)
    # Handle the branch where not target_validation['success'] evaluates to true.
    if not target_validation["success"]:
        return {"success": False, "error": target_validation["error"]}

    # Handle the branch where exclude_targets evaluates to true.
    if exclude_targets:
        import ipaddress
        # Run this block with structured exception handling.
        try:
            scan_net = ipaddress.ip_network(network_info["cidr"], strict=False)
            targets = [t.strip() for t in re.split(r'[,\s]+', exclude_targets) if t.strip()]
            # Iterate over targets and bind each item to target.
            for target in targets:
                # Run this block with structured exception handling.
                try:
                    # Handle the branch where '/' in target evaluates to true.
                    if "/" in target:
                        target_net = ipaddress.ip_network(target, strict=False)
                        # Handle the branch where not scan_net.supernet_of(target_net) evaluates to true.
                        if not scan_net.supernet_of(target_net):
                            return {"success": False, "error": f"Exclusion target subnet {target} is outside of the scan target range {network_info['cidr']}."}
                    # Handle the fallback branch when the preceding condition does not match.
                    else:
                        target_ip = ipaddress.ip_address(target)
                        # Handle the branch where target_ip not in scan_net evaluates to true.
                        if target_ip not in scan_net:
                            return {"success": False, "error": f"Exclusion target IP {target} is outside of the scan target range {network_info['cidr']}."}
                # Handle an exception raised by the preceding protected block.
                except ValueError:
                    return {"success": False, "error": f"Invalid exclusion target format: {target}"}
        # Handle an exception raised by the preceding protected block.
        except ValueError:
            return {"success": False, "error": "Invalid scan target CIDR."}

    return {"success": True, "network_info": network_info}

# Handle the scan operation.
@scan_bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        # Handle the branch where _user_available_for_new_scan(current_user.id) is None evaluates to true.
        if _user_available_for_new_scan(current_user.id) is None:
            flash("This account is being deleted and cannot start new scans.", "error")
            return redirect(url_for("scan.scan"))
        # Handle the branch where is_scan_frozen() evaluates to true.
        if is_scan_frozen():
            flash("Scan blocked due to Scan Blackout Window", "error")
            return redirect(url_for("scan.scan"))
            
        ip_address = request.form.get("ip_address", "").strip()
        subnet_mask = request.form.get("subnet_mask", "").strip()
        scan_type = request.form.get("scan_type", "").strip()
        ports = request.form.get("ports", "").replace(" ", "").strip()
        timing_template = request.form.get("timing_template", "4").strip()
        exclude_targets = request.form.get("exclude_targets", "").strip()
        selected_creds = request.form.getlist("credential_ids")
        audit_credentials = request.form.get("audit_credentials") == "y"

        # Handle the branch where not ip_address or not scan_type evaluates to true.
        if not ip_address or not scan_type:
            flash("Please fill in all required scan fields.", "error")
            return redirect(url_for("scan.scan"))

        validation = validate_scan_request(
            ip_address=ip_address,
            subnet_mask=subnet_mask,
            scan_type=scan_type,
            ports=ports,
            timing_template=timing_template,
            credential_ids=selected_creds,
            user_id=current_user.id,
            exclude_targets=exclude_targets
        )
        # Handle the branch where not validation['success'] evaluates to true.
        if not validation["success"]:
            flash(validation["error"], "error")
            return redirect(url_for("scan.scan"))

        network_info = validation["network_info"]
        credential_ids_str = ",".join(selected_creds) if selected_creds else None

        scan_result = ScanResult(
            user_id=current_user.id,
            input_ip=ip_address,
            subnet_mask=subnet_mask if subnet_mask else "N/A",
            scan_type=scan_type,
            ports=ports if ports else None,
            network_cidr=network_info["cidr"],
            first_host=network_info["first_host"],
            last_host=network_info["last_host"],
            exclude_targets=exclude_targets if exclude_targets else None,
            credential_ids=credential_ids_str,
            timing_template=timing_template,
            audit_credentials=audit_credentials,
            status="pending",
            scheduled_for=datetime.now(timezone.utc).replace(tzinfo=None),
            scheduler_dispatch_state="queued",
            scheduler_attempt_count=0,
            scheduler_max_attempts=current_app.config["SCHEDULER_MAX_ATTEMPTS"],
        )
        db.session.add(scan_result)
        db.session.commit()

        return redirect(url_for("scan.result", scan_id=scan_result.id))

    admin_user = User.query.filter_by(is_admin=True).first()
    admin_setting = SystemSetting.query.filter_by(user_id=admin_user.id).first() if admin_user else None
    is_frozen = False
    freeze_start = "09:00"
    freeze_end = "17:00"
    # Handle the branch where admin_setting evaluates to true.
    if admin_setting:
        freeze_start = admin_setting.scan_freeze_start
        freeze_end = admin_setting.scan_freeze_end
        # Handle the branch where admin_setting.scan_freeze_active evaluates to true.
        if admin_setting.scan_freeze_active:
            is_frozen = is_in_freeze_window(freeze_start, freeze_end)

    user_credentials = ScanCredential.query.filter_by(user_id=current_user.id).order_by(ScanCredential.name).all()

    return render_template(
        "scan.html",
        is_frozen=is_frozen,
        freeze_start=freeze_start,
        freeze_end=freeze_end,
        user_credentials=user_credentials
    )

# Handle the stop scan operation.
@scan_bp.route("/scan/<int:scan_id>/stop", methods=["POST"])
@login_required
def stop_scan(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where not user_can_view_scan(scan_result) evaluates to true.
    if not user_can_view_scan(scan_result):
        flash("You are not authorised to stop this scan.", "error")
        return redirect(url_for("scan.scan"))

    # Handle the branch where scan_result.status == 'pending' evaluates to true.
    if scan_result.status == "pending":
        cancelled = ScanResult.query.filter(
            ScanResult.id == scan_id,
            ScanResult.status == "pending",
        ).update(
            {
                ScanResult.status: "cancelled",
                ScanResult.scheduler_dispatch_state: "cancelled",
                ScanResult.scheduler_execution_phase: "cancelled",
            },
            synchronize_session=False,
        )
        db.session.commit()
        # Handle the branch where cancelled == 1 evaluates to true.
        if cancelled == 1:
            flash("Scan execution cancelled.", "success")
            return redirect(url_for("scan.result", scan_id=scan_id))
        db.session.expire_all()
        scan_result = db.session.get(ScanResult, scan_id)

    # Handle the branch where scan_result and scan_result.status in ['running', 'termination_failed'] evaluates to true.
    if scan_result and scan_result.status in ["running", "termination_failed"]:
        from scanner import stop_scan_process

        expected_status = scan_result.status
        expected_token = scan_result.scheduler_claim_token
        expected_phase = scan_result.scheduler_execution_phase
        is_local_owner = (
            scan_result.scheduler_worker_id == current_app.config["SCAN_WORKER_ID"]
            and scan_result.scheduler_process_id == os.getpid()
        )
        stop_result = (
            stop_scan_process(scan_id, expected_token) if is_local_owner else None
        )
        cancellation_secured = bool(
            stop_result
            and (
                (
                    not stop_result.had_processes
                    and (
                        stop_result.start_permission_revoked
                        or (
                            expected_phase == "starting"
                            and stop_result.all_processes_stopped
                        )
                    )
                )
                or (
                    stop_result.had_processes
                    and stop_result.all_processes_stopped
                )
            )
        )
        token_condition = (
            ScanResult.scheduler_claim_token == expected_token
            if expected_token is not None
            # Handle the fallback branch when the preceding condition does not match.
            else ScanResult.scheduler_claim_token.is_(None)
        )
        new_values = (
            {
                ScanResult.status: "cancellation_requested",
                ScanResult.scheduler_dispatch_state: "cancellation_requested",
                ScanResult.scheduler_execution_phase: "cancellation_requested",
            }
            if cancellation_secured
            # Handle the fallback branch when the preceding condition does not match.
            else {
                ScanResult.status: "termination_failed",
                ScanResult.scheduler_dispatch_state: "orphaned",
                ScanResult.scheduler_execution_phase: "termination_failed",
            }
        )
        updated = ScanResult.query.filter(
            ScanResult.id == scan_id,
            ScanResult.status == expected_status,
            token_condition,
        ).update(new_values, synchronize_session=False)
        db.session.commit()
        # Handle the branch where updated != 1 evaluates to true.
        if updated != 1:
            flash("Scan state changed before cancellation; terminal state was preserved.", "warning")
        # Handle the branch where cancellation_secured evaluates to true.
        elif cancellation_secured:
            flash(
                "Scan cancellation requested; capacity will be released when "
                "the owning worker exits.",
                "success",
            )
        # Handle the fallback branch when the preceding condition does not match.
        else:
            flash(
                "The scan process could not be confirmed terminated and still "
                "consumes concurrency capacity.",
                "error",
            )
    # Handle the fallback branch when the preceding condition does not match.
    else:
        flash("Scan is not in a cancellable state.", "warning")

    return redirect(url_for("scan.result", scan_id=scan_result.id))

# Handle the repeat scan operation.
@scan_bp.route("/scan/<int:scan_id>/repeat", methods=["POST"])
@login_required
def repeat_scan(scan_id):
    # Handle the branch where _user_available_for_new_scan(current_user.id) is None evaluates to true.
    if _user_available_for_new_scan(current_user.id) is None:
        flash("This account is being deleted and cannot start new scans.", "error")
        return redirect(url_for("scan.scan"))
    # Handle the branch where is_scan_frozen() evaluates to true.
    if is_scan_frozen():
        flash("Scan blocked due to Scan Blackout Window", "error")
        return redirect(url_for("scan.scan"))
        
    old_scan = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where not user_can_view_scan(old_scan) evaluates to true.
    if not user_can_view_scan(old_scan):
        flash("You are not authorised to repeat this scan.", "error")
        return redirect(url_for("scan.scan"))
        
    network_info = calculate_network(old_scan.input_ip, old_scan.subnet_mask if old_scan.subnet_mask != "N/A" else None)
    # Handle the branch where not network_info['success'] evaluates to true.
    if not network_info["success"]:
        flash(f"Invalid scan target: {network_info['error']}", "error")
        return redirect(url_for("scan.scan"))
        
    target_validation = validate_scan_target(network_info, old_scan.scan_type)
    # Handle the branch where not target_validation['success'] evaluates to true.
    if not target_validation["success"]:
        flash(target_validation["error"], "error")
        return redirect(url_for("scan.scan"))
        
    scan_result = ScanResult(
        user_id=current_user.id,
        input_ip=old_scan.input_ip,
        subnet_mask=old_scan.subnet_mask,
        scan_type=old_scan.scan_type,
        ports=old_scan.ports,
        network_cidr=old_scan.network_cidr,
        first_host=old_scan.first_host,
        last_host=old_scan.last_host,
        exclude_targets=old_scan.exclude_targets,
        credential_ids=old_scan.credential_ids,
        timing_template=old_scan.timing_template,
        audit_credentials=old_scan.audit_credentials,
        status="pending",
        scheduled_for=datetime.now(timezone.utc).replace(tzinfo=None),
        scheduler_dispatch_state="queued",
        scheduler_attempt_count=0,
        scheduler_max_attempts=current_app.config["SCHEDULER_MAX_ATTEMPTS"],
    )
    db.session.add(scan_result)
    db.session.commit()
    
    flash("Repeated scan queued.", "success")
    return redirect(url_for("scan.result", scan_id=scan_result.id))

# Handle the history operation.
@scan_bp.route("/history")
@login_required
def history():
    scan_results = ScanResult.query.filter_by(
        user_id=current_user.id
    ).order_by(
        ScanResult.created_at.desc()
    ).all()

    has_active_scans = any(
        scan.status in [
            "pending",
            "running",
            "cancellation_requested",
            "termination_failed",
        ]
        for scan in scan_results
    )

    return render_template(
        "history.html",
        scan_results=scan_results,
        has_active_scans=has_active_scans
    )

# Handle the result operation.
@scan_bp.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where not user_can_view_scan(scan_result) evaluates to true.
    if not user_can_view_scan(scan_result):
        flash("You are not authorised to view this scan result.", "error")
        return redirect(url_for("scan.scan"))

    parsed_result = None
    # Handle the branch where scan_result.result_data evaluates to true.
    if scan_result.result_data:
        # Run this block with structured exception handling.
        try:
            parsed_result = json.loads(scan_result.result_data)
        # Handle an exception raised by the preceding protected block.
        except json.JSONDecodeError:
            parsed_result = {
                "command": "Legacy text output",
                "output": scan_result.result_data,
                "hosts": []
            }

    return render_template(
        "result.html",
        scan_result=scan_result,
        parsed_result=parsed_result
    )

# Handle the result report operation.
@scan_bp.route("/result/<int:scan_id>/report")
@login_required
def result_report(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where not user_can_view_scan(scan_result) evaluates to true.
    if not user_can_view_scan(scan_result):
        flash("You are not authorised to view this report.", "error")
        return redirect(url_for("scan.scan"))

    parsed_result = None
    # Handle the branch where scan_result.result_data evaluates to true.
    if scan_result.result_data:
        # Run this block with structured exception handling.
        try:
            parsed_result = json.loads(scan_result.result_data)
        # Handle an exception raised by the preceding protected block.
        except json.JSONDecodeError:
            parsed_result = {
                "command": "Legacy text output",
                "output": scan_result.result_data,
                "hosts": []
            }

    return render_template(
        "report.html",
        scan_result=scan_result,
        parsed_result=parsed_result
    )

# Handle the export result csv operation.
@scan_bp.route("/result/<int:scan_id>/export/csv")
@login_required
def export_result_csv(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where not user_can_view_scan(scan_result) evaluates to true.
    if not user_can_view_scan(scan_result):
        flash("You are not authorised to export this scan result.", "error")
        return redirect(url_for("scan.scan"))

    # Handle the branch where not scan_result.result_data evaluates to true.
    if not scan_result.result_data:
        flash("No result data available for export.", "error")
        return redirect(url_for("scan.result", scan_id=scan_result.id))

    # Run this block with structured exception handling.
    try:
        parsed_result = json.loads(scan_result.result_data)
    # Handle an exception raised by the preceding protected block.
    except json.JSONDecodeError:
        flash("This scan result is not available in structured format.", "error")
        return redirect(url_for("scan.result", scan_id=scan_result.id))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Created At", "Input IP", "Subnet Mask", "Calculated Network",
        "Scan Type", "Scanned Ports", "Scan Status", "Executed Command",
        "Host", "Hostname", "Host Status", "Port", "Protocol", "Port State", "Service", "Version"
    ])

    hosts = parsed_result.get("hosts", [])
    # Handle the branch where hosts evaluates to true.
    if hosts:
        # Iterate over hosts and bind each item to host.
        for host in hosts:
            ports = host.get("ports", [])
            # Handle the branch where ports evaluates to true.
            if ports:
                # Iterate over ports and bind each item to port.
                for port in ports:
                    writer.writerow([
                        scan_result.id, format_local_datetime(scan_result.created_at),
                        scan_result.input_ip, scan_result.subnet_mask, scan_result.network_cidr,
                        scan_name_filter(scan_result.scan_type), scan_result.ports if scan_result.ports else "Default",
                        scan_result.status, parsed_result.get("command", ""),
                        host.get("address", ""), host.get("hostname", ""), host.get("status", ""),
                        port.get("port", ""), port.get("protocol", ""), port.get("state", ""),
                        port.get("service", ""), port.get("version", "")
                    ])
            # Handle the fallback branch when the preceding condition does not match.
            else:
                writer.writerow([
                    scan_result.id, format_local_datetime(scan_result.created_at),
                    scan_result.input_ip, scan_result.subnet_mask, scan_result.network_cidr,
                    scan_name_filter(scan_result.scan_type), scan_result.ports if scan_result.ports else "Default",
                    scan_result.status, parsed_result.get("command", ""),
                    host.get("address", ""), host.get("hostname", ""), host.get("status", ""),
                    "", "", "", "", ""
                ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=lynceus_scan_{scan_result.id}.csv"}
    )

# Handle the export result json operation.
@scan_bp.route("/result/<int:scan_id>/export/json")
@login_required
def export_result_json(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where not user_can_view_scan(scan_result) evaluates to true.
    if not user_can_view_scan(scan_result):
        flash("You are not authorised to export this scan result.", "error")
        return redirect(url_for("scan.scan"))

    # Handle the branch where not scan_result.result_data evaluates to true.
    if not scan_result.result_data:
        flash("No result data available for export.", "error")
        return redirect(url_for("scan.result", scan_id=scan_result.id))

    # Run this block with structured exception handling.
    try:
        parsed_result = json.loads(scan_result.result_data)
    # Handle an exception raised by the preceding protected block.
    except json.JSONDecodeError:
        flash("This scan result is not available in structured format.", "error")
        return redirect(url_for("scan.result", scan_id=scan_result.id))

    export_data = {
        "scan_id": scan_result.id,
        "created_at": format_local_datetime(scan_result.created_at),
        "input_ip": scan_result.input_ip,
        "subnet_mask": scan_result.subnet_mask,
        "network_cidr": scan_result.network_cidr,
        "scan_type": scan_result.scan_type,
        "ports": scan_result.ports,
        "status": scan_result.status,
        "results": parsed_result
    }

    return Response(
        json.dumps(export_data, indent=4),
        mimetype="application/json",
        headers={"Content-disposition": f"attachment; filename=lynceus_scan_{scan_result.id}.json"}
    )

# Handle the export result txt operation.
@scan_bp.route("/result/<int:scan_id>/export/txt")
@login_required
def export_result_txt(scan_id):
    scan_result = ScanResult.query.get_or_404(scan_id)
    # Handle the branch where not user_can_view_scan(scan_result) evaluates to true.
    if not user_can_view_scan(scan_result):
        flash("You are not authorised to export this scan result.", "error")
        return redirect(url_for("scan.scan"))

    # Handle the branch where not scan_result.result_data evaluates to true.
    if not scan_result.result_data:
        flash("No result data available for export.", "error")
        return redirect(url_for("scan.result", scan_id=scan_result.id))

    # Run this block with structured exception handling.
    try:
        parsed_result = json.loads(scan_result.result_data)
    # Handle an exception raised by the preceding protected block.
    except json.JSONDecodeError:
        flash("This scan result is not available in structured format.", "error")
        return redirect(url_for("scan.result", scan_id=scan_result.id))

    lines = []
    lines.append("=========================================")
    lines.append("           LYNCEUS SCAN REPORT           ")
    lines.append("=========================================")
    lines.append(f"Scan ID: {scan_result.id}")
    lines.append(f"Scan Target: {scan_result.input_ip} (Subnet: {scan_result.subnet_mask})")
    lines.append(f"Calculated CIDR: {scan_result.network_cidr}")
    lines.append(f"Scan Type: {scan_name_filter(scan_result.scan_type)}")
    lines.append(f"Scan Status: {scan_result.status}")
    lines.append(f"Created At: {format_local_datetime(scan_result.created_at)}")
    lines.append(f"Executed Command: {parsed_result.get('command', 'N/A')}")
    lines.append("=========================================\n")

    hosts = parsed_result.get("hosts", [])
    # Handle the branch where hosts evaluates to true.
    if hosts:
        # Iterate over hosts and bind each item to host.
        for host in hosts:
            lines.append(f"Host: {host.get('address', '')} ({host.get('hostname', 'Unknown hostname')})")
            lines.append(f"Host Status: {host.get('status', '')}")
            # Handle the branch where host.get('mac_address') evaluates to true.
            if host.get("mac_address"):
                lines.append(f"MAC Address: {host.get('mac_address')} ({host.get('mac_vendor', 'Unknown vendor')})")
            
            ports = host.get("ports", [])
            # Handle the branch where ports evaluates to true.
            if ports:
                lines.append("Open Ports:")
                # Iterate over ports and bind each item to port.
                for port in ports:
                    lines.append(f"  - {port.get('port')}/{port.get('protocol')} [{port.get('state')}] -> {port.get('service')} {port.get('version') or ''}")
            # Handle the fallback branch when the preceding condition does not match.
            else:
                lines.append("No open ports discovered.")
            lines.append("-----------------------------------------")

    return Response(
        "\n".join(lines),
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename=lynceus_scan_{scan_result.id}.txt"}
    )

# Handle the schedules operation.
@scan_bp.route("/schedules")
@login_required
def schedules():
    schedule_list = ScanSchedule.query.filter_by(user_id=current_user.id).order_by(ScanSchedule.created_at.desc()).all()
    return render_template("schedules.html", schedules=schedule_list)

# Handle the new schedule operation.
@scan_bp.route("/schedules/new", methods=["GET", "POST"])
@login_required
def new_schedule():
    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        subnet_mask = request.form.get("subnet_mask", "").strip()
        scan_type = request.form.get("scan_type", "").strip()
        ports = request.form.get("ports", "").replace(" ", "").strip()
        frequency = request.form.get("frequency", "").strip()
        timing_template = request.form.get("timing_template", "4").strip()
        exclude_targets = request.form.get("exclude_targets", "").strip()
        selected_creds = request.form.getlist("credential_ids")
        audit_credentials = request.form.get("audit_credentials") == "y"

        # Handle the branch where not name or not ip_address or (not scan_type) or (not frequency) evaluates to true.
        if not name or not ip_address or not scan_type or not frequency:
            flash("Please fill in all required scheduling fields.", "error")
            return redirect(url_for("scan.new_schedule"))

        validation = validate_scan_request(
            ip_address=ip_address,
            subnet_mask=subnet_mask,
            scan_type=scan_type,
            ports=ports,
            timing_template=timing_template,
            credential_ids=selected_creds,
            user_id=current_user.id,
            exclude_targets=exclude_targets,
            frequency=frequency
        )
        # Handle the branch where not validation['success'] evaluates to true.
        if not validation["success"]:
            flash(validation["error"], "error")
            return redirect(url_for("scan.new_schedule"))

        network_info = validation["network_info"]
        credential_ids_str = ",".join(selected_creds) if selected_creds else None

        # Database times MUST be UTC
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        next_run = now
        # Handle the branch where frequency == 'hourly' evaluates to true.
        if frequency == "hourly":
            next_run = now + timedelta(hours=1)
        # Handle the branch where frequency == 'daily' evaluates to true.
        elif frequency == "daily":
            next_run = now + timedelta(days=1)
        # Handle the branch where frequency == 'weekly' evaluates to true.
        elif frequency == "weekly":
            next_run = now + timedelta(weeks=1)
        # Handle the branch where frequency == 'monthly' evaluates to true.
        elif frequency == "monthly":
            next_run = now + timedelta(days=30)

        sched = ScanSchedule(
            user_id=current_user.id,
            name=name,
            input_ip=ip_address,
            subnet_mask=subnet_mask if subnet_mask else "N/A",
            scan_type=scan_type,
            ports=ports if ports else None,
            network_cidr=network_info["cidr"],
            frequency=frequency,
            next_run=next_run,
            is_active=True,
            exclude_targets=exclude_targets if exclude_targets else None,
            credential_ids=credential_ids_str,
            timing_template=timing_template,
            audit_credentials=audit_credentials
        )
        db.session.add(sched)
        db.session.commit()
        flash("Scan schedule successfully created.", "success")
        return redirect(url_for("scan.schedules"))

    user_credentials = ScanCredential.query.filter_by(user_id=current_user.id).order_by(ScanCredential.name).all()
    return render_template("schedule_form.html", schedule=None, user_credentials=user_credentials)

# Handle the edit schedule operation.
@scan_bp.route("/schedules/<int:schedule_id>/edit", methods=["GET", "POST"])
@login_required
def edit_schedule(schedule_id):
    sched = ScanSchedule.query.filter_by(id=schedule_id, user_id=current_user.id).first_or_404()
    # Handle the branch where request.method == 'POST' evaluates to true.
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        subnet_mask = request.form.get("subnet_mask", "").strip()
        scan_type = request.form.get("scan_type", "").strip()
        ports = request.form.get("ports", "").replace(" ", "").strip()
        frequency = request.form.get("frequency", "").strip()
        timing_template = request.form.get("timing_template", "4").strip()
        exclude_targets = request.form.get("exclude_targets", "").strip()
        selected_creds = request.form.getlist("credential_ids")
        audit_credentials = request.form.get("audit_credentials") == "y"

        # Handle the branch where not name or not ip_address or (not scan_type) or (not frequency) evaluates to true.
        if not name or not ip_address or not scan_type or not frequency:
            flash("Please fill in all required scheduling fields.", "error")
            return redirect(url_for("scan.edit_schedule", schedule_id=sched.id))

        validation = validate_scan_request(
            ip_address=ip_address,
            subnet_mask=subnet_mask,
            scan_type=scan_type,
            ports=ports,
            timing_template=timing_template,
            credential_ids=selected_creds,
            user_id=current_user.id,
            exclude_targets=exclude_targets,
            frequency=frequency
        )
        # Handle the branch where not validation['success'] evaluates to true.
        if not validation["success"]:
            flash(validation["error"], "error")
            return redirect(url_for("scan.edit_schedule", schedule_id=sched.id))

        network_info = validation["network_info"]

        # Recalculate next run if frequency has changed
        if sched.frequency != frequency:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            # Handle the branch where frequency == 'hourly' evaluates to true.
            if frequency == "hourly":
                sched.next_run = now + timedelta(hours=1)
            # Handle the branch where frequency == 'daily' evaluates to true.
            elif frequency == "daily":
                sched.next_run = now + timedelta(days=1)
            # Handle the branch where frequency == 'weekly' evaluates to true.
            elif frequency == "weekly":
                sched.next_run = now + timedelta(weeks=1)
            # Handle the branch where frequency == 'monthly' evaluates to true.
            elif frequency == "monthly":
                sched.next_run = now + timedelta(days=30)

        sched.name = name
        sched.input_ip = ip_address
        sched.subnet_mask = subnet_mask if subnet_mask else "N/A"
        sched.scan_type = scan_type
        sched.ports = ports if ports else None
        sched.frequency = frequency
        sched.timing_template = timing_template
        sched.exclude_targets = exclude_targets if exclude_targets else None
        sched.credential_ids = ",".join(selected_creds) if selected_creds else None
        sched.audit_credentials = audit_credentials
        sched.network_cidr = network_info["cidr"]

        db.session.commit()
        flash("Scan schedule updated successfully.", "success")
        return redirect(url_for("scan.schedules"))

    user_credentials = ScanCredential.query.filter_by(user_id=current_user.id).order_by(ScanCredential.name).all()
    return render_template("schedule_form.html", schedule=sched, user_credentials=user_credentials)

# Handle the toggle schedule operation.
@scan_bp.route("/schedules/<int:schedule_id>/toggle", methods=["POST"])
@login_required
def toggle_schedule(schedule_id):
    sched = ScanSchedule.query.filter_by(id=schedule_id, user_id=current_user.id).first_or_404()
    sched.is_active = not sched.is_active
    db.session.commit()
    status_str = "activated" if sched.is_active else "paused"
    flash(f"Schedule '{sched.name}' has been {status_str}.", "success")
    return redirect(url_for("scan.schedules"))

# Delete schedule.
@scan_bp.route("/schedules/<int:schedule_id>/delete", methods=["POST"])
@login_required
def delete_schedule(schedule_id):
    sched = ScanSchedule.query.filter_by(id=schedule_id, user_id=current_user.id).first_or_404()
    db.session.delete(sched)
    db.session.commit()
    flash("Schedule deleted successfully.", "success")
    return redirect(url_for("scan.schedules"))

# Handle the bulk delete schedules operation.
@scan_bp.route("/schedules/bulk-delete", methods=["POST"])
@login_required
def bulk_delete_schedules():
    schedule_ids = request.form.getlist("schedule_ids")
    # Handle the branch where not schedule_ids evaluates to true.
    if not schedule_ids:
        flash("No scan schedules selected for deletion.", "warning")
        return redirect(url_for("scan.schedules"))

    # Run this block with structured exception handling.
    try:
        int_ids = [int(sid) for sid in schedule_ids]
        deleted_count = ScanSchedule.query.filter(
            ScanSchedule.id.in_(int_ids),
            ScanSchedule.user_id == current_user.id
        ).delete(synchronize_session=False)
        db.session.commit()
        flash(f"Successfully deleted {deleted_count} scan schedules.", "success")
    # Handle an exception raised by the preceding protected block.
    except Exception as e:
        db.session.rollback()
        flash(f"Error during bulk deletion: {str(e)}", "error")

    return redirect(url_for("scan.schedules"))

# Handle the compare scans operation.
@scan_bp.route("/scans/compare")
@login_required
def compare_scans():
    scan_a_id = request.args.get("scan_a")
    scan_b_id = request.args.get("scan_b")
    # Handle the branch where not scan_a_id or not scan_b_id evaluates to true.
    if not scan_a_id or not scan_b_id:
        flash("Please select two scans to compare.", "warning")
        return redirect(url_for("scan.history"))

    scan_a = ScanResult.query.get_or_404(scan_a_id)
    scan_b = ScanResult.query.get_or_404(scan_b_id)
    # Handle the branch where not user_can_view_scan(scan_a) or not user_can_view_scan(scan_b) evaluates to true.
    if not user_can_view_scan(scan_a) or not user_can_view_scan(scan_b):
        flash("You are not authorized to view these scans.", "error")
        return redirect(url_for("scan.history"))

    # Handle the branch where scan_a.status != 'completed' or scan_b.status != 'completed' evaluates to true.
    if scan_a.status != "completed" or scan_b.status != "completed":
        flash("Both scans must be completed to compare.", "error")
        return redirect(url_for("scan.history"))

    data_a = json.loads(scan_a.result_data) if scan_a.result_data else {"hosts": []}
    data_b = json.loads(scan_b.result_data) if scan_b.result_data else {"hosts": []}
    hosts_a = {h["address"]: h for h in data_a.get("hosts", [])}
    hosts_b = {h["address"]: h for h in data_b.get("hosts", [])}

    added_hosts = []
    removed_hosts = []
    modified_hosts = []

    # Iterate over hosts_b.items() and bind each item to (ip, host).
    for ip, host in hosts_b.items():
        # Handle the branch where ip not in hosts_a evaluates to true.
        if ip not in hosts_a:
            added_hosts.append(host)
        # Handle the fallback branch when the preceding condition does not match.
        else:
            ports_a = {int(p["port"]): p for p in hosts_a[ip].get("ports", [])}
            ports_b = {int(p["port"]): p for p in host.get("ports", [])}
            
            added_ports = [p for port_num, p in ports_b.items() if port_num not in ports_a]
            removed_ports = [p for port_num, p in ports_a.items() if port_num not in ports_b]
            
            changed_services = []
            # Iterate over ports_b.items() and bind each item to (port_num, port_b).
            for port_num, port_b in ports_b.items():
                # Handle the branch where port_num in ports_a evaluates to true.
                if port_num in ports_a:
                    port_a = ports_a[port_num]
                    # Handle the branch where port_a.get('service') != port_b.get('service') or port_a.get('version') != port_b.get('version') evaluates to true.
                    if port_a.get("service") != port_b.get("service") or port_a.get("version") != port_b.get("version"):
                        changed_services.append({"port": port_num, "old": port_a, "new": port_b})
            
            # Handle the branch where added_ports or removed_ports or changed_services evaluates to true.
            if added_ports or removed_ports or changed_services:
                modified_hosts.append({
                    "address": ip,
                    "hostname": host.get("hostname", ""),
                    "added_ports": added_ports,
                    "removed_ports": removed_ports,
                    "changed_services": changed_services
                })

    # Iterate over hosts_a.items() and bind each item to (ip, host).
    for ip, host in hosts_a.items():
        # Handle the branch where ip not in hosts_b evaluates to true.
        if ip not in hosts_b:
            removed_hosts.append(host)

    return render_template(
        "compare.html",
        scan_a=scan_a,
        scan_b=scan_b,
        added_hosts=added_hosts,
        removed_hosts=removed_hosts,
        modified_hosts=modified_hosts
    )
