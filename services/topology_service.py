import os
import subprocess
import re
import socket
from models import Asset, SecurityAnomaly
from services.device_classifier import classify_device_type

# Handle the detect default gateway operation.
def detect_default_gateway():
    """
    Tries to detect the default gateway IP address of the host machine.
    """
    # Run this block with structured exception handling.
    try:
        # Handle the branch where os.name == 'nt' evaluates to true.
        if os.name == 'nt':
            out = subprocess.check_output(["route", "print"], text=True, errors="ignore")
            # Iterate over out.splitlines() and bind each item to line.
            for line in out.splitlines():
                line = line.strip()
                # Handle the branch where line.startswith('0.0.0.0') evaluates to true.
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    # Handle the branch where len(parts) >= 5 evaluates to true.
                    if len(parts) >= 5:
                        # Destination Netmask Gateway Interface Metric
                        return parts[2]
        # Handle the fallback branch when the preceding condition does not match.
        else:
            out = subprocess.check_output(["ip", "route"], text=True, errors="ignore")
            # Iterate over out.splitlines() and bind each item to line.
            for line in out.splitlines():
                # Handle the branch where line.startswith('default via') evaluates to true.
                if line.startswith("default via"):
                    return line.split()[2]
    # Handle an exception raised by the preceding protected block.
    except Exception:
        pass
    
    return None

# Retrieve system arp table.
def get_system_arp_table():
    """
    Parses the system ARP table to find IP-MAC mappings.
    """
    arp_entries = []
    # Run this block with structured exception handling.
    try:
        # Handle the branch where os.name == 'nt' evaluates to true.
        if os.name == 'nt':
            out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
            # Iterate over out.splitlines() and bind each item to line.
            for line in out.splitlines():
                line = line.strip()
                # Handle the branch where not line or line.startswith('Interface:') or line.startswith('Internet Address') evaluates to true.
                if not line or line.startswith("Interface:") or line.startswith("Internet Address"):
                    continue
                parts = line.split()
                # Handle the branch where len(parts) >= 3 evaluates to true.
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1].replace('-', ':').lower()
                    type_str = parts[2]
                    arp_entries.append({"ip": ip, "mac": mac, "type": type_str})
        # Handle the fallback branch when the preceding condition does not match.
        else:
            out = subprocess.check_output(["arp", "-n"], text=True, errors="ignore")
            # Iterate over out.splitlines()[1:] and bind each item to line.
            for line in out.splitlines()[1:]:
                parts = line.split()
                # Handle the branch where len(parts) >= 3 evaluates to true.
                if len(parts) >= 3:
                    arp_entries.append({"ip": parts[0], "mac": parts[2].lower(), "type": "dynamic"})
    # Handle an exception raised by the preceding protected block.
    except Exception:
        pass
    return arp_entries

# Handle the classify device operation.
def classify_device(ip, mac, hostname, vendor, open_ports, is_gateway=False):
    return classify_device_type(
        hostname,
        vendor,
        open_ports,
        is_gateway=is_gateway,
    )

# Retrieve network topology.
def get_network_topology(assets, scan_results=None):
    """
    Builds nodes and edges for network topology visualization.
    Uses traceroute hops when available, default gateways, and ARP tables.
    """
    gateway_ip = detect_default_gateway()
    arp_table = get_system_arp_table()
    arp_map = {entry["ip"]: entry["mac"] for entry in arp_table}

    # Query unresolved anomalies
    anomalies = SecurityAnomaly.query.filter_by(is_resolved=False).all()
    anomaly_ips = {a.ip_address for a in anomalies if a.ip_address}
    anomaly_macs = {a.mac_address.lower() for a in anomalies if a.mac_address}

    # Group assets by subnet
    def get_subnet_prefix(ip_str):
        # Handle the branch where not ip_str evaluates to true.
        if not ip_str:
            return "Unknown Subnet"
        match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$", ip_str.strip())
        # Handle the branch where match evaluates to true.
        if match:
            return f"{match.group(1)}.0/24"
        return "Unknown Subnet"

    nodes = []
    edges = []
    seen_nodes = set()

    # Use the inventory asset itself as the core when it is the default gateway.
    # This avoids drawing the same modem/router as both Gateway and Host nodes.
    gateway_asset = next(
        (asset for asset in assets if asset.ip_address.strip() == gateway_ip),
        None,
    ) if gateway_ip else None
    gateway_id = (
        f"host_{gateway_ip}"
        if gateway_asset is not None
        # Handle the fallback branch when the preceding condition does not match.
        else (f"gateway_{gateway_ip}" if gateway_ip else "gateway_core")
    )

    # Handle the branch where gateway_asset is not None evaluates to true.
    if gateway_asset is not None:
        gateway_has_anomaly = (
            gateway_asset.ip_address in anomaly_ips
            or (
                gateway_asset.mac_address
                and gateway_asset.mac_address.lower() in anomaly_macs
            )
        )
        # Handle the branch where gateway_has_anomaly evaluates to true.
        if gateway_has_anomaly:
            gateway_color = {"background": "#e53e3e", "border": "#9b2c2c"}
            gateway_title = "Default Gateway / Active Anomalies"
        # Handle the branch where not gateway_asset.is_trusted evaluates to true.
        elif not gateway_asset.is_trusted:
            gateway_color = {"background": "#dd6b20", "border": "#9c4221"}
            gateway_title = "Default Gateway / Untrusted Device"
        # Handle the fallback branch when the preceding condition does not match.
        else:
            gateway_color = {"background": "#2d3748", "border": "#1a202c"}
            gateway_title = "Default Gateway / Inventory Asset"

        last_seen = (
            gateway_asset.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            if gateway_asset.last_seen
            # Handle the fallback branch when the preceding condition does not match.
            else "Never"
        )
        nodes.append({
            "id": gateway_id,
            "label": f"{gateway_asset.name or 'Gateway'}\n({gateway_ip})",
            "type": "Router",
            "title": gateway_title,
            "color": gateway_color,
            "ip": gateway_ip,
            "mac": gateway_asset.mac_address or arp_map.get(gateway_ip, "N/A"),
            "details": {
                "ip": gateway_ip,
                "mac": gateway_asset.mac_address or "N/A",
                "vendor": gateway_asset.mac_vendor or "Unknown",
                "device_type": "Router",
                "operating_system": gateway_asset.operating_system or "Unknown",
                "criticality": gateway_asset.criticality or "Medium",
                "is_trusted": gateway_asset.is_trusted,
                "last_seen": last_seen,
                "asset_id": gateway_asset.id,
                "network_role": "Default Gateway",
            },
            "level": 0,
        })
    # Handle the fallback branch when the preceding condition does not match.
    else:
        gateway_label = f"Gateway\n({gateway_ip})" if gateway_ip else "Lynceus Gateway"
        nodes.append({
            "id": gateway_id,
            "label": gateway_label,
            "type": "Router",
            "title": "Default Gateway",
            "color": {
                "background": "#2d3748",
                "border": "#1a202c"
            },
            "ip": gateway_ip or "0.0.0.0",
            "mac": arp_map.get(gateway_ip, "N/A") if gateway_ip else "N/A",
            "level": 0
        })
    seen_nodes.add(gateway_id)

    # Group assets by subnet
    subnets = {}
    # Iterate over assets and bind each item to asset.
    for asset in assets:
        ip = asset.ip_address.strip()
        subnet = get_subnet_prefix(ip)
        # Handle the branch where subnet not in subnets evaluates to true.
        if subnet not in subnets:
            subnets[subnet] = []
        subnets[subnet].append(asset)

    # Iterate over subnets.items() and bind each item to (subnet, subnet_assets).
    for subnet, subnet_assets in subnets.items():
        subnet_node_id = f"subnet_{subnet}"
        # Handle the branch where subnet_node_id not in seen_nodes evaluates to true.
        if subnet_node_id not in seen_nodes:
            nodes.append({
                "id": subnet_node_id,
                "label": f"Subnet\n{subnet}",
                "type": "Subnet",
                "title": "Subnet Segment",
                "color": {
                    "background": "#718096",
                    "border": "#4a5568"
                },
                "level": 1
            })
            seen_nodes.add(subnet_node_id)
            
            # Connect gateway to subnet
            edges.append({
                "id": f"edge_gw_{subnet_node_id}",
                "from": gateway_id,
                "to": subnet_node_id,
                "label": "VLAN/Subnet"
            })

        # Iterate over subnet_assets and bind each item to asset.
        for asset in subnet_assets:
            host_node_id = f"host_{asset.ip_address}"
            # Handle the branch where host_node_id not in seen_nodes evaluates to true.
            if host_node_id not in seen_nodes:
                # Try to parse open ports from the last completed scan if results are passed
                open_ports = []
                connected_to_traceroute = False
                
                # Handle the branch where scan_results evaluates to true.
                if scan_results:
                    # Iterate over scan_results and bind each item to scan.
                    for scan in scan_results:
                        # Handle the branch where not scan.result_data evaluates to true.
                        if not scan.result_data:
                            continue
                        # Run this block with structured exception handling.
                        try:
                            import json
                            data = json.loads(scan.result_data)
                            # Iterate over data.get('hosts', []) and bind each item to host.
                            for host in data.get("hosts", []):
                                # Handle the branch where host.get('address') == asset.ip_address evaluates to true.
                                if host.get("address") == asset.ip_address:
                                    open_ports = host.get("ports", [])
                                    # Check traceroute
                                    if "trace" in host and host["trace"]:
                                        trace = host["trace"]
                                        prev_hop_id = gateway_id
                                        # Iterate over trace and bind each item to hop.
                                        for hop in trace:
                                            hop_ip = hop.get("ipaddr")
                                            # Handle the branch where not hop_ip evaluates to true.
                                            if not hop_ip:
                                                continue
                                            hop_node_id = (
                                                gateway_id
                                                if hop_ip == gateway_ip
                                                # Handle the fallback branch when the preceding condition does not match.
                                                else f"hop_{hop_ip}"
                                            )
                                            # Handle the branch where hop_node_id not in seen_nodes evaluates to true.
                                            if hop_node_id not in seen_nodes:
                                                nodes.append({
                                                    "id": hop_node_id,
                                                    "label": f"Hop {hop.get('hop')}\n{hop_ip}",
                                                    "type": "Router",
                                                    "title": "Network Hop Node",
                                                    "color": {
                                                        "background": "#4a5d4e",
                                                        "border": "#2f3e33"
                                                    },
                                                    "ip": hop_ip,
                                                    "level": 1
                                                })
                                                seen_nodes.add(hop_node_id)
                                                # Connect previous hop to this hop
                                                edges.append({
                                                    "id": f"edge_{prev_hop_id}_{hop_node_id}",
                                                    "from": prev_hop_id,
                                                    "to": hop_node_id
                                                })
                                            prev_hop_id = hop_node_id
                                        
                                        # Connect last hop to the target host node
                                        edges.append({
                                            "id": f"edge_{prev_hop_id}_{host_node_id}",
                                            "from": prev_hop_id,
                                            "to": host_node_id
                                        })
                                        connected_to_traceroute = True
                                        break
                        # Handle an exception raised by the preceding protected block.
                        except Exception:
                            pass
                        # Handle the branch where connected_to_traceroute evaluates to true.
                        if connected_to_traceroute:
                            break
                
                device_type = classify_device(
                    asset.ip_address,
                    asset.mac_address,
                    asset.name,
                    asset.mac_vendor,
                    open_ports,
                    is_gateway=(asset.ip_address == gateway_ip)
                )
                
                # Check for active anomalies
                has_anomaly = False
                # Handle the branch where asset.ip_address in anomaly_ips evaluates to true.
                if asset.ip_address in anomaly_ips:
                    has_anomaly = True
                # Handle the branch where asset.mac_address and asset.mac_address.lower() in anomaly_macs evaluates to true.
                if asset.mac_address and asset.mac_address.lower() in anomaly_macs:
                    has_anomaly = True
                
                # Handle the branch where has_anomaly evaluates to true.
                if has_anomaly:
                    color = {"background": "#e53e3e", "border": "#9b2c2c"}
                    title = "Active Anomalies"
                # Handle the branch where not asset.is_trusted evaluates to true.
                elif not asset.is_trusted:
                    color = {"background": "#dd6b20", "border": "#9c4221"}
                    title = "Untrusted Device"
                # Handle the fallback branch when the preceding condition does not match.
                else:
                    color = {"background": "#2b6cb0", "border": "#1a365d"}
                    title = "Trusted Endpoint"

                last_seen_str = asset.last_seen.strftime("%Y-%m-%d %H:%M:%S") if asset.last_seen else "Never"
                
                nodes.append({
                    "id": host_node_id,
                    "label": f"{asset.name or asset.ip_address}\n({asset.ip_address})",
                    "type": device_type,
                    "title": title,
                    "color": color,
                    "details": {
                        "ip": asset.ip_address,
                        "mac": asset.mac_address or "N/A",
                        "vendor": asset.mac_vendor or "Unknown",
                        "device_type": device_type,
                        "operating_system": asset.operating_system or "Unknown",
                        "criticality": asset.criticality or "Medium",
                        "is_trusted": asset.is_trusted,
                        "last_seen": last_seen_str,
                        "asset_id": asset.id
                    },
                    "level": 2
                })
                seen_nodes.add(host_node_id)
                
                # Handle the branch where not connected_to_traceroute evaluates to true.
                if not connected_to_traceroute:
                    # Connect directly to subnet node
                    edges.append({
                        "id": f"edge_{subnet_node_id}_{host_node_id}",
                        "from": subnet_node_id,
                        "to": host_node_id
                    })

    return {"nodes": nodes, "edges": edges}
