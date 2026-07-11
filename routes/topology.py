from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user

from models import Asset, ScanResult
from services.topology_service import get_network_topology

topology_bp = Blueprint("topology", __name__)

@topology_bp.route("/topology")
@login_required
def view_topology():
    return render_template("topology.html")

@topology_bp.route("/api/topology")
@login_required
def get_topology_data():
    assets = Asset.query.all()
    scan_results = ScanResult.query.filter_by(
        user_id=current_user.id,
        status="completed"
    ).order_by(ScanResult.created_at.desc()).all()
    
    topology_data = get_network_topology(assets, scan_results=scan_results)
    return jsonify(topology_data)
