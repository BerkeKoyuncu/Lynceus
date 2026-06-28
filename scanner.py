import ipaddress
import subprocess
import shutil
import os
import xml.etree.ElementTree as ET


def calculate_network(ip_address, subnet_mask=None):
    """
    Calculates the network address, CIDR notation, and usable host range.
    Supports standard subnets (with subnet mask) and custom targets
    (ranges, CIDR notation, comma-separated IPs, single IPs) when subnet_mask is omitted.
    """
    ip_address = ip_address.strip()
    
    # Check if subnet_mask is provided and valid
    if subnet_mask and subnet_mask.strip() and subnet_mask.strip().lower() not in ["none", "n/a", "null", "-"]:
        subnet_mask = subnet_mask.strip()
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

    # Otherwise, it's a range, CIDR, list, or single IP
    target = ip_address

    # 1. CIDR notation (e.g. 192.168.1.0/24)
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            all_hosts = list(network.hosts())
            return {
                "success": True,
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address) if hasattr(network, "broadcast_address") else "N/A",
                "cidr": str(network),
                "first_host": str(all_hosts[0]) if all_hosts else str(network.network_address),
                "last_host": str(all_hosts[-1]) if all_hosts else str(network.network_address),
                "total_addresses": network.num_addresses,
                "usable_hosts": len(all_hosts) if all_hosts else 1
            }
        except ValueError as error:
            return {"success": False, "error": f"Invalid CIDR: {str(error)}"}

    # 2. Comma-separated (e.g. 192.168.1.5,192.168.1.6)
    if "," in target:
        parts = [p.strip() for p in target.split(",") if p.strip()]
        if not parts:
            return {"success": False, "error": "Empty target list."}
        
        total_ips = 0
        first_host = None
        last_host = None
        for p in parts:
            p_info = calculate_network(p)
            if not p_info["success"]:
                return p_info
            total_ips += p_info["total_addresses"]
            if not first_host:
                first_host = p_info["first_host"]
            last_host = p_info["last_host"]
            
        return {
            "success": True,
            "network_address": "Multiple Targets",
            "broadcast_address": "N/A",
            "cidr": target,
            "first_host": first_host,
            "last_host": last_host,
            "total_addresses": total_ips,
            "usable_hosts": total_ips
        }

    # 3. Hyphenated range (e.g. 192.168.1.10-40 or 192.168.1.10-192.168.1.40)
    if "-" in target:
        parts = target.split("-")
        if len(parts) != 2:
            return {"success": False, "error": "Invalid range format. Use e.g. 192.168.1.10-40"}
        
        start_part = parts[0].strip()
        end_part = parts[1].strip()

        try:
            start_ip = ipaddress.IPv4Address(start_part)
            if "." in end_part:
                end_ip = ipaddress.IPv4Address(end_part)
            else:
                # Octet shorthand (e.g. 192.168.1.10-40)
                octets = start_part.split(".")
                if len(octets) != 4:
                    return {"success": False, "error": "Invalid start IP format."}
                octets[-1] = end_part
                end_ip_str = ".".join(octets)
                end_ip = ipaddress.IPv4Address(end_ip_str)

            if start_ip > end_ip:
                return {"success": False, "error": "Start IP is greater than End IP in range."}

            num_ips = int(end_ip) - int(start_ip) + 1

            # Convert to Nmap-compatible target format
            start_octets = str(start_ip).split(".")
            end_octets = str(end_ip).split(".")
            if start_octets[:3] == end_octets[:3]:
                # Suffix range (e.g. 10.0.0.1-20)
                nmap_target = f"{'.'.join(start_octets[:3])}.{start_octets[-1]}-{end_octets[-1]}"
            else:
                # Spans multiple subnets: expand to comma-separated list of individual IPs
                ips = [str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
                nmap_target = ",".join(ips)

            return {
                "success": True,
                "network_address": "Range",
                "broadcast_address": "N/A",
                "cidr": nmap_target,
                "first_host": str(start_ip),
                "last_host": str(end_ip),
                "total_addresses": num_ips,
                "usable_hosts": num_ips
            }
        except ValueError as error:
            return {"success": False, "error": f"Invalid range IP format: {str(error)}"}

    # 4. Single IP (e.g. 192.168.1.15)
    try:
        ip = ipaddress.IPv4Address(target)
        return {
            "success": True,
            "network_address": str(ip),
            "broadcast_address": "N/A",
            "cidr": str(ip),
            "first_host": str(ip),
            "last_host": str(ip),
            "total_addresses": 1,
            "usable_hosts": 1
        }
    except ValueError as error:
        return {"success": False, "error": f"Invalid IP address format: {str(error)}"}


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


def is_target_vpn_via_nmap(target, nmap_executable):
    """
    Checks if any of the target IPs/subnets route through a VPN or virtual adapter
    using Nmap's language-independent interface list.
    """
    import socket
    import ipaddress
    import subprocess
    import re

    # Split targets if comma-separated
    target_list = [t.strip() for t in target.split(",") if t.strip()]
    if not target_list:
        return False

    # Get Nmap interface list (cached or run once)
    nmap_interfaces = []
    try:
        completed = subprocess.run(
            [nmap_executable, "--iflist"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if completed.returncode == 0:
            nmap_interfaces = completed.stdout.splitlines()
    except Exception:
        pass

    if not nmap_interfaces:
        return False

    for single_target in target_list:
        # Resolve test IP for this target
        ip_to_test = None
        if any(char in single_target for char in ["-", "*"]):
            match = re.match(r'^([\d\.]+)', single_target)
            if match:
                ip_to_test = match.group(1)
        else:
            try:
                net = ipaddress.ip_network(single_target, strict=False)
                if net.num_addresses > 1:
                    ip_to_test = str(next(net.hosts()))
                else:
                    ip_to_test = str(net.network_address)
            except ValueError:
                ip_to_test = single_target

        if not ip_to_test:
            continue

        # Get local routing IP for this destination IP
        local_ip = None
        try:
            resolved_ip = socket.gethostbyname(ip_to_test)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((resolved_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        if not local_ip:
            continue

        # Check if local_ip belongs to a VPN/Tunnel adapter in Nmap's interface list
        for line in nmap_interfaces:
            if local_ip in line:
                parts = line.split()
                if len(parts) >= 3:
                    dev = parts[0].lower()
                    # Check if TYPE is point2point or dev name indicates tunnel/vpn
                    if "point2point" in line.lower() or any(kw in dev for kw in ["tun", "tap", "vpn", "ppp"]):
                        return True
                    
    return False


def discover_active_hosts(target, timeout=0.4):
    """
    Performs a fast, parallel TCP connect-based host discovery on a target subnet in Python.
    Works reliably over VPNs and standard network interfaces without administrative privileges.
    """
    import socket
    import ipaddress
    import concurrent.futures
    import errno

    # Parse target network
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts())
    except ValueError:
        return [target]

    if len(hosts) <= 1:
        return [target]

    # Ports to check for activity (most common enterprise/service ports)
    common_ports = [80, 443, 22, 3389, 445, 135, 8080]
    active_hosts = []

    def probe_host_port(ip_str, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip_str, port))
            s.close()
            # 0 means connection success
            # ECONNREFUSED means connection refused (host is up, port closed)
            if result == 0 or result == errno.ECONNREFUSED:
                return True
        except Exception:
            pass
        return False

    def check_host_status(ip_str):
        for port in common_ports:
            if probe_host_port(ip_str, port):
                return ip_str
        return None

    # Limit to max 128 threads to avoid resource limits
    max_workers = min(128, len(hosts))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host_status, str(host)): str(host) for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                active_hosts.append(res)

    return active_hosts


def sanitize_exclusion_string(exclude_str):
    """
    Sanitizes and converts exclusion targets into Nmap-compatible format.
    Specifically, it converts hyphenated full IP ranges (e.g. 10.0.0.1-10.0.0.3)
    into Nmap-compatible octet suffix ranges (e.g. 10.0.0.1-3) or comma-separated lists.
    """
    if not exclude_str:
        return ""
    
    sanitized_parts = []
    # Split by commas and sanitize each part
    parts = [p.strip() for p in exclude_str.split(",") if p.strip()]
    for part in parts:
        res = calculate_network(part)
        if res["success"]:
            sanitized_parts.append(res["cidr"])
        else:
            # Fallback to the original part if parsing failed (could be a hostname)
            sanitized_parts.append(part)
            
    return ",".join(sanitized_parts)


import threading

active_processes = {}
active_processes_lock = threading.Lock()

class CompletedProcessDummy:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

def execute_nmap_subprocess(command, scan_id=None):
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if scan_id is not None:
        with active_processes_lock:
            active_processes[scan_id] = proc
    try:
        stdout, stderr = proc.communicate(timeout=600)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        returncode = -1
    finally:
        if scan_id is not None:
            with active_processes_lock:
                active_processes.pop(scan_id, None)
    return returncode, stdout, stderr

def stop_scan_process(scan_id):
    with active_processes_lock:
        proc = active_processes.get(scan_id)
        if proc:
            try:
                proc.kill()
                return True
            except Exception:
                pass
    return False


def run_nmap_scan(target, scan_type, ports=None, exclude_targets=None, timing_template="4", scan_id=None):
    """
    Runs an Nmap scan and returns structured results.
    """
    if exclude_targets:
        exclude_targets = sanitize_exclusion_string(exclude_targets)

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

    flags = scan_configs[scan_type].copy()

    # Sanitize timing_template
    if not timing_template or timing_template not in ["0", "1", "2", "3", "4", "5"]:
        timing_template = "4"

    # Override or append the timing template flag
    timing_flag = f"-T{timing_template}"
    has_replaced_timing = False
    for idx, flag in enumerate(flags):
        if flag.startswith("-T") and len(flag) == 3 and flag[2].isdigit():
            flags[idx] = timing_flag
            has_replaced_timing = True
            break
    
    if not has_replaced_timing:
        flags.append(timing_flag)
    
    is_fallback = False
    original_command = None

    # Pre-scan VPN check (language-independent via Nmap --iflist)
    is_vpn_detected = False
    if os.name == "nt":
        try:
            is_vpn_detected = is_target_vpn_via_nmap(target, nmap_executable)
        except Exception:
            pass

    if is_vpn_detected:
        adjusted_flags = []
        for flag in flags:
            if flag == "-sS" or flag == "-sU":
                adjusted_flags.append("-sT")
            else:
                adjusted_flags.append(flag)
        flags = adjusted_flags
        
        if "--unprivileged" not in flags:
            flags.append("--unprivileged")
            
        # Determine if target is a single host or a subnet range
        is_single_host = True
        if any(char in target for char in ["-", ",", "*"]):
            is_single_host = False
        else:
            try:
                net = ipaddress.ip_network(target, strict=False)
                if net.num_addresses > 1:
                    is_single_host = False
            except ValueError:
                pass
        
        if is_single_host and "-Pn" not in flags:
            flags.append("-Pn")

        is_fallback = True
        cmd_parts = [nmap_executable] + scan_configs[scan_type]
        if ports and scan_type != "ping_sweep":
            cmd_parts += ["-p", ports]
        if exclude_targets:
            cmd_parts += ["--exclude", exclude_targets]
        cmd_parts += ["-oX", "-", target]
        original_command = " ".join(cmd_parts)

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
        command = [nmap_executable] + custom_flags + ["-p", ports]
    else:
        command = [nmap_executable] + flags

    if exclude_targets:
        command += ["--exclude", exclude_targets]

    command += ["-oX", "-", target]

    try:
        returncode, stdout, stderr = execute_nmap_subprocess(command, scan_id)
        completed_process = CompletedProcessDummy(returncode, stdout, stderr)

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
                command = [nmap_executable] + flags + ["-p", ports]
            else:
                command = [nmap_executable] + flags

            if exclude_targets:
                command += ["--exclude", exclude_targets]

            command += ["-oX", "-", target]

            returncode_fb, stdout_fb, stderr_fb = execute_nmap_subprocess(command, scan_id)
            completed_process = CompletedProcessDummy(returncode_fb, stdout_fb, stderr_fb)
            stdout = completed_process.stdout
            stderr = completed_process.stderr

        hosts = []

        if stdout:
            hosts = parse_nmap_xml(stdout)

        # Determine if target is a single host or a subnet range
        is_single_host = True
        if any(char in target for char in ["-", ",", "*"]):
            is_single_host = False
        else:
            try:
                net = ipaddress.ip_network(target, strict=False)
                if net.num_addresses > 1:
                    is_single_host = False
            except ValueError:
                pass

        # VPN / Network adapter fallback logic:
        # If the scan completed successfully but found 0 hosts, it could be a VPN virtual adapter
        # where Npcap raw packets/ARP requests fail. Fall back to socket-based unprivileged TCP scan.
        if completed_process.returncode == 0 and len(hosts) == 0:
            if is_single_host:
                fallback_command = []
                for arg in command[:-1]:
                    if arg == "-sS" or arg == "-sU":
                        fallback_command.append("-sT")
                    else:
                        fallback_command.append(arg)
                fallback_command.append(target)
                
                if "--unprivileged" not in fallback_command:
                    fallback_command.append("--unprivileged")
                if "-Pn" not in fallback_command:
                    fallback_command.append("-Pn")
                
                try:
                    retcode, f_stdout, f_stderr = execute_nmap_subprocess(fallback_command, scan_id)
                    fallback_process = CompletedProcessDummy(retcode, f_stdout, f_stderr)
                    
                    if fallback_process.returncode == 0:
                        fallback_stdout = fallback_process.stdout
                        if fallback_stdout:
                            fallback_hosts = parse_nmap_xml(fallback_stdout)
                            if len(fallback_hosts) > 0:
                                completed_process = fallback_process
                                stdout = fallback_stdout
                                stderr = fallback_process.stderr
                                hosts = fallback_hosts
                                is_fallback = True
                                original_command = " ".join(command)
                                command = fallback_command
                except Exception:
                    pass
            else:
                # Subnet: Run Python-based host discovery first to find online hosts
                try:
                    active_ips = discover_active_hosts(target)
                    if active_ips:
                        target_list = ",".join(active_ips)
                        fallback_command = []
                        for arg in command[:-1]:
                            if arg == "-sS" or arg == "-sU":
                                fallback_command.append("-sT")
                            else:
                                fallback_command.append(arg)
                        fallback_command.append(target_list)
                        
                        if "--unprivileged" not in fallback_command:
                            fallback_command.append("--unprivileged")
                        if "-Pn" not in fallback_command:
                            fallback_command.append("-Pn")
                            
                        retcode, f_stdout, f_stderr = execute_nmap_subprocess(fallback_command, scan_id)
                        fallback_process = CompletedProcessDummy(retcode, f_stdout, f_stderr)
                        
                        if fallback_process.returncode == 0:
                            fallback_stdout = fallback_process.stdout
                            if fallback_stdout:
                                fallback_hosts = parse_nmap_xml(fallback_stdout)
                                if len(fallback_hosts) > 0:
                                    completed_process = fallback_process
                                    stdout = fallback_stdout
                                    stderr = fallback_process.stderr
                                    hosts = fallback_hosts
                                    is_fallback = True
                                    original_command = " ".join(command)
                                    command = fallback_command
                except Exception:
                    pass

        final_output = stderr if stderr else ""
        if is_fallback:
            if original_command:
                fallback_note = f"[INFO] VPN/Virtual Adapter or privilege issue detected. Automatically fell back to unprivileged scan.\n[Original Command]: {original_command}\n\n"
            else:
                fallback_note = "[INFO] SYN scan requires administrative privileges. Automatically fell back to TCP Connect scan (-sT).\n"
            final_output = fallback_note + final_output

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
    
def is_ip_allowed(ip_str):
    """
    Helper to check if a single IP address belongs to the allowed private/loopback/link-local scopes.
    """
    if not ip_str or ip_str == "N/A":
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def is_target_safe(target_str):
    """
    Safely verifies if all IP addresses in the target string are allowed (private/loopback/link-local).
    Iteratively parses comma-separated lists and hyphenated ranges without recursion.
    """
    if not target_str:
        return False

    # 1. Split comma-separated targets and process iteratively
    sub_targets = [p.strip() for p in target_str.split(",") if p.strip()]
    if not sub_targets:
        return False

    for target in sub_targets:
        # 2. Check hyphenated range (e.g. 192.168.1.10-40 or 192.168.1.10-192.168.1.40)
        if "-" in target:
            parts = target.split("-")
            if len(parts) != 2:
                return False
            start_part = parts[0].strip()
            end_part = parts[1].strip()
            
            if not start_part:
                return False

            # Support octet shorthand (e.g., 192.168.1.10-40)
            if "." not in end_part:
                dots = start_part.split(".")
                if len(dots) == 4:
                    end_part = f"{dots[0]}.{dots[1]}.{dots[2]}.{end_part}"
                else:
                    return False
            
            if not is_ip_allowed(start_part) or not is_ip_allowed(end_part):
                return False

        # 3. Check CIDR notation or single IP address
        else:
            try:
                network = ipaddress.ip_network(target, strict=False)
                if network.is_multicast or network.is_unspecified or network.is_reserved:
                    return False
                if not (network.is_private or network.is_loopback or network.is_link_local):
                    return False
            except ValueError:
                return False

    return True

def validate_scan_target(network_info, scan_type):
    """
    Validates whether the calculated network is safe and reasonable to scan.
    """

    try:
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

        total_addresses = network_info.get("total_addresses", 1)

        if total_addresses > max_allowed_addresses:
            return {
                "success": False,
                "error": (
                    f"The selected network is too large for {scan_type} scan. "
                    f"Maximum allowed size is {max_allowed_addresses} IP addresses."
                )
            }

        if not is_target_safe(network_info.get("cidr")):
            return {
                "success": False,
                "error": "Only private, loopback, or link-local networks are allowed to be scanned."
            }

        return {"success": True, "error": None}

    except Exception as error:
        return {
            "success": False,
            "error": str(error)
        }