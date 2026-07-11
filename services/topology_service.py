import os
import subprocess
import re
import socket
from models import Asset, SecurityAnomaly

def detect_default_gateway():
    """
    Tries to detect the default gateway IP address of the host machine.
    """
    try:
        if os.name == 'nt':
            out = subprocess.check_output(["route", "print"], text=True, errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 5:
                        # Destination Netmask Gateway Interface Metric
                        return parts[2]
        else:
            out = subprocess.check_output(["ip", "route"], text=True, errors="ignore")
            for line in out.splitlines():
                if line.startswith("default via"):
                    return line.split()[2]
    except Exception:
        pass
    
    return None

def get_system_arp_table():
    """
    Parses the system ARP table to find IP-MAC mappings.
    """
    arp_entries = []
    try:
        if os.name == 'nt':
            out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if not line or line.startswith("Interface:") or line.startswith("Internet Address"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1].replace('-', ':').lower()
                    type_str = parts[2]
                    arp_entries.append({"ip": ip, "mac": mac, "type": type_str})
        else:
            out = subprocess.check_output(["arp", "-n"], text=True, errors="ignore")
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    arp_entries.append({"ip": parts[0], "mac": parts[2].lower(), "type": "dynamic"})
    except Exception:
        pass
    return arp_entries

def classify_device(ip, mac, hostname, vendor, open_ports, is_gateway=False):
    """
    Heuristic classifier for devices based on ports, vendor, and gateway status.
    """
    if is_gateway:
        return "Router"

    # Infrastructure keywords
    infra_vendors = ["cisco", "ubiquiti", "mikrotik", "netgear", "d-link", "tp-link", "hp", "juniper", "huawei", "linksys"]
    vendor_lower = (vendor or "").lower()
    for brand in infra_vendors:
        if brand in vendor_lower:
            return "Switch"

    # Ports check
    port_nums = [int(p.get("port") or 0) for p in open_ports] if isinstance(open_ports, list) else []
    # If SNMP is open, or Telnet + SSH are both open on infrastructure vendor
    if 161 in port_nums or 162 in port_nums:
        return "Switch"
    
    if (22 in port_nums or 23 in port_nums) and any(b in (hostname or "").lower() for b in ["switch", "router", "gateway", "ap-"]):
        return "Router" if "router" in (hostname or "").lower() else "Switch"

    # Standard endpoint classes
    if any(os_keyword in (hostname or "").lower() for os_keyword in ["win", "pc", "desktop", "laptop"]):
        return "Workstation"
    host_lower = (hostname or "").lower()
    
    ports_set = {int(p.get("port", 0)) for p in open_ports if p.get("port")}
    
    if 53 in ports_set or 67 in ports_set or 68 in ports_set:
        return "Network Switch"
        
    if "cisco" in vendor_lower or "netgear" in vendor_lower or "tp-link" in vendor_lower:
        return "Network Switch"
        
    if 631 in ports_set or 9100 in ports_set or "printer" in host_lower or "hp" in vendor_lower:
        return "Printer"
        
    if 22 in ports_set or 80 in ports_set or 443 in ports_set or 8080 in ports_set:
        return "Server"
        
    return "Workstation"

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
        if not ip_str:
            return "Unknown Subnet"
        match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$", ip_str.strip())
        if match:
            return f"{match.group(1)}.0/24"
        return "Unknown Subnet"

    nodes = []
    edges = []
    seen_nodes = set()

    # Core node representing the default gateway or Lynceus itself
    gateway_label = f"Gateway\n({gateway_ip})" if gateway_ip else "Lynceus Gateway"
    gateway_id = f"gateway_{gateway_ip}" if gateway_ip else "gateway_core"
    
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
    for asset in assets:
        ip = asset.ip_address.strip()
        subnet = get_subnet_prefix(ip)
        if subnet not in subnets:
            subnets[subnet] = []
        subnets[subnet].append(asset)

    for subnet, subnet_assets in subnets.items():
        subnet_node_id = f"subnet_{subnet}"
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

        for asset in subnet_assets:
            host_node_id = f"host_{asset.ip_address}"
            if host_node_id not in seen_nodes:
                # Try to parse open ports from the last completed scan if results are passed
                open_ports = []
                connected_to_traceroute = False
                
                if scan_results:
                    for scan in scan_results:
                        if not scan.result_data:
                            continue
                        try:
                            import json
                            data = json.loads(scan.result_data)
                            for host in data.get("hosts", []):
                                if host.get("address") == asset.ip_address:
                                    open_ports = host.get("ports", [])
                                    # Check traceroute
                                    if "trace" in host and host["trace"]:
                                        trace = host["trace"]
                                        prev_hop_id = gateway_id
                                        for hop in trace:
                                            hop_ip = hop.get("ipaddr")
                                            if not hop_ip:
                                                continue
                                            hop_node_id = f"hop_{hop_ip}"
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
                        except Exception:
                            pass
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
                if asset.ip_address in anomaly_ips:
                    has_anomaly = True
                if asset.mac_address and asset.mac_address.lower() in anomaly_macs:
                    has_anomaly = True
                
                if has_anomaly:
                    color = {"background": "#e53e3e", "border": "#9b2c2c"}
                    title = "Active Anomalies"
                elif not asset.is_trusted:
                    color = {"background": "#dd6b20", "border": "#9c4221"}
                    title = "Untrusted Device"
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
                
                if not connected_to_traceroute:
                    # Connect directly to subnet node
                    edges.append({
                        "id": f"edge_{subnet_node_id}_{host_node_id}",
                        "from": subnet_node_id,
                        "to": host_node_id
                    })

    return {"nodes": nodes, "edges": edges}
