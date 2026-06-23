import ipaddress
import subprocess
import shutil
import os
import xml.etree.ElementTree as ET


def calculate_network(ip_address, subnet_mask):
    """
    Calculates the network address, CIDR notation, and usable host range
    from a given IP address and subnet mask.
    """

    try:
        network = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)

        all_hosts = list(network.hosts())

        if all_hosts:
            first_host = str(all_hosts[0])
            last_host = str(all_hosts[-1])
        else:
            first_host = "N/A"
            last_host = "N/A"

        return {
            "success": True,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "cidr": str(network),
            "first_host": first_host,
            "last_host": last_host,
            "total_addresses": network.num_addresses,
            "usable_hosts": len(all_hosts)
        }

    except ValueError as error:
        return {
            "success": False,
            "error": str(error)
        }


def find_nmap_executable():
    """
    Finds the Nmap executable on Windows or through PATH.
    """

    nmap_from_path = shutil.which("nmap")

    if nmap_from_path:
        return nmap_from_path

    possible_paths = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe"
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return path

    return None


def parse_nmap_xml(xml_output):
    """
    Parses Nmap XML output into structured scan data.
    """

    parsed_hosts = []

    root = ET.fromstring(xml_output)

    for host in root.findall("host"):
        status_element = host.find("status")
        host_status = status_element.get("state") if status_element is not None else "unknown"

        ip_address = "unknown"
        mac_address = ""
        mac_vendor = ""

        for address_el in host.findall("address"):
            addr_type = address_el.get("addrtype", "")
            if addr_type in ["ipv4", "ipv6"]:
                ip_address = address_el.get("addr", "unknown")
            elif addr_type == "mac":
                mac_address = address_el.get("addr", "")
                mac_vendor = address_el.get("vendor", "")

        hostname = ""

        hostnames_element = host.find("hostnames")
        if hostnames_element is not None:
            hostname_element = hostnames_element.find("hostname")
            if hostname_element is not None:
                hostname = hostname_element.get("name", "")

        ports_data = []

        ports_element = host.find("ports")
        if ports_element is not None:
            for port in ports_element.findall("port"):
                protocol = port.get("protocol", "")
                port_number = port.get("portid", "")

                state_element = port.find("state")
                state = state_element.get("state") if state_element is not None else ""

                service_element = port.find("service")
                service_name = ""
                product = ""
                version = ""
                extra_info = ""

                if service_element is not None:
                    service_name = service_element.get("name", "")
                    product = service_element.get("product", "")
                    version = service_element.get("version", "")
                    extra_info = service_element.get("extrainfo", "")

                version_info = " ".join(
                    item for item in [product, version, extra_info] if item
                )

                ports_data.append({
                    "port": port_number,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "version": version_info if version_info else "-"
                })

        parsed_hosts.append({
            "address": ip_address,
            "mac_address": mac_address,
            "mac_vendor": mac_vendor,
            "hostname": hostname,
            "status": host_status,
            "ports": ports_data
        })

    return parsed_hosts


def run_nmap_scan(target, scan_type, ports=None):
    """
    Runs an Nmap scan and returns structured results.
    """

    nmap_executable = find_nmap_executable()

    if not nmap_executable:
        return {
            "success": False,
            "command": "nmap",
            "output": "Nmap was not found. Please make sure Nmap is installed and added to PATH.",
            "hosts": []
        }

    # Map scan types to command flags
    scan_configs = {
        "fast": ["-F"],
        "service_version": ["-sV", "-T4"],
        "ping_sweep": ["-sn"],
        "syn": ["-sS"],
        "connect": ["-sT"],
        "udp": ["-sU", "--top-ports", "100"],
        "aggressive": ["-A", "-T4"],
        "vuln": ["-sV", "-T4", "--script", "vuln"],
        # Legacy fallbacks
        "quick": ["-F"],
        "detailed": ["-sV", "-T4"]
    }

    if scan_type not in scan_configs:
        return {
            "success": False,
            "command": "Invalid scan type",
            "output": "Invalid scan type.",
            "hosts": []
        }

    flags = scan_configs[scan_type]
    
    if ports and scan_type != "ping_sweep":
        custom_flags = []
        skip_next = False
        for flag in flags:
            if skip_next:
                skip_next = False
                continue
            if flag == "--top-ports":
                skip_next = True
                continue
            if flag == "-F":
                continue
            custom_flags.append(flag)
        command = [nmap_executable] + custom_flags + ["-p", ports] + ["-oX", "-", target]
    else:
        command = [nmap_executable] + flags + ["-oX", "-", target]

    is_fallback = False
    original_command = None

    try:
        completed_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600
        )

        stdout = completed_process.stdout
        stderr = completed_process.stderr

        # Check if SYN scan failed due to privilege/admin rights
        if (
            scan_type == "syn"
            and completed_process.returncode != 0
            and any(err in (stderr + stdout).lower() for err in ["privilege", "permission denied", "dnet", "root", "socket-bind"])
        ):
            is_fallback = True
            original_command = " ".join(command)
            flags = scan_configs["connect"]
            
            if ports:
                command = [nmap_executable] + flags + ["-p", ports] + ["-oX", "-", target]
            else:
                command = [nmap_executable] + flags + ["-oX", "-", target]

            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600
            )
            stdout = completed_process.stdout
            stderr = completed_process.stderr

        hosts = []

        if stdout:
            hosts = parse_nmap_xml(stdout)

        final_output = stderr if stderr else ""
        if is_fallback:
            fallback_note = "[INFO] SYN scan requires administrative privileges. Automatically fell back to TCP Connect scan (-sT).\n"
            final_output = fallback_note + f"[Original Command]: {original_command}\n\n" + final_output

        return {
            "success": completed_process.returncode == 0,
            "command": " ".join(command),
            "output": final_output,
            "hosts": hosts
        }

    except ET.ParseError as error:
        return {
            "success": False,
            "command": " ".join(command),
            "output": f"Failed to parse Nmap XML output: {str(error)}",
            "hosts": []
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": " ".join(command),
            "output": "The scan timed out. The target network may be too large or unreachable.",
            "hosts": []
        }

    except Exception as error:
        return {
            "success": False,
            "command": " ".join(command),
            "output": f"Unexpected error: {str(error)}",
            "hosts": []
        }
    
def validate_scan_target(network_info, scan_type):
    """
    Validates whether the calculated network is safe and reasonable to scan.
    """

    try:
        network = ipaddress.ip_network(network_info["cidr"], strict=False)

        max_addresses_by_scan_type = {
            "fast": 1024,
            "service_version": 256,
            "ping_sweep": 2048,
            "syn": 512,
            "connect": 512,
            "udp": 64,
            "aggressive": 64,
            "vuln": 64,
            # Legacy fallbacks
            "quick": 1024,
            "detailed": 256
        }

        max_allowed_addresses = max_addresses_by_scan_type.get(scan_type)

        if max_allowed_addresses is None:
            return {
                "success": False,
                "error": "Invalid scan type selected."
            }

        if network.num_addresses > max_allowed_addresses:
            return {
                "success": False,
                "error": (
                    f"The selected network is too large for {scan_type} scan. "
                    f"Maximum allowed size is {max_allowed_addresses} IP addresses."
                )
            }

        if network.is_multicast:
            return {
                "success": False,
                "error": "Multicast networks cannot be scanned."
            }

        if network.is_unspecified:
            return {
                "success": False,
                "error": "Unspecified networks cannot be scanned."
            }

        if network.is_reserved:
            return {
                "success": False,
                "error": "Reserved networks cannot be scanned."
            }

        if not (
            network.is_private
            or network.is_loopback
            or network.is_link_local
        ):
            return {
                "success": False,
                "error": "Only private, loopback, or link-local networks are allowed."
            }

        return {
            "success": True,
            "error": None
        }

    except ValueError as error:
        return {
            "success": False,
            "error": str(error)
        }