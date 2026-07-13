import ipaddress
import subprocess
import shutil
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass

# Modules used to validate IP targets, run Nmap commands, and convert XML
# results into dictionaries and lists consumed by the application.

def calculate_network(ip_address, subnet_mask=None):
    """
    Calculates the network address, CIDR notation, and usable host range.
    Supports standard subnets (with subnet mask) and custom targets
    (ranges, CIDR notation, comma-separated IPs, single IPs) when subnet_mask is omitted.
    """
    ip_address = ip_address.strip()
    
    # If a valid subnet mask is provided, calculate the IP and mask as one network.
    if subnet_mask and subnet_mask.strip() and subnet_mask.strip().lower() not in ["none", "n/a", "null", "-"]:
        subnet_mask = subnet_mask.strip()
        # Run this block with structured exception handling.
        try:
            network = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)
            num_addresses = network.num_addresses
            # In a /32 network, the only address is itself the usable target.
            if num_addresses == 1:
                first_host = str(network.network_address)
                last_host = str(network.network_address)
                usable_hosts = 1
            # In a /31 network, both addresses are usable for point-to-point links.
            elif num_addresses == 2:
                first_host = str(network.network_address)
                last_host = str(network.network_address + 1)
                usable_hosts = 2
            # For larger networks, exclude the network and broadcast addresses.
            else:
                first_host = str(network.network_address + 1)
                last_host = str(network.broadcast_address - 1)
                usable_hosts = num_addresses - 2
            return {
                "success": True,
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address),
                "cidr": str(network),
                "first_host": first_host,
                "last_host": last_host,
                "total_addresses": num_addresses,
                "usable_hosts": usable_hosts
            }
        # Return a descriptive error when the IP address or subnet mask is invalid.
        except ValueError as error:
            return {
                "success": False,
                "error": str(error)
            }

    # Without a mask, interpret the input as CIDR, a list, a range, or a single IP.
    target = ip_address

    # Parse CIDR notation, such as 192.168.1.0/24.
    if "/" in target:
        # Run this block with structured exception handling.
        try:
            network = ipaddress.ip_network(target, strict=False)
            num_addresses = network.num_addresses
            # Determine the first and last usable addresses from the network size.
            if num_addresses == 1:
                first_host = str(network.network_address)
                last_host = str(network.network_address)
                usable_hosts = 1
            # Handle the branch where num_addresses == 2 evaluates to true.
            elif num_addresses == 2:
                first_host = str(network.network_address)
                last_host = str(network.network_address + 1)
                usable_hosts = 2
            # Handle the fallback branch when the preceding condition does not match.
            else:
                first_host = str(network.network_address + 1)
                last_host = str(network.broadcast_address - 1)
                usable_hosts = num_addresses - 2
            return {
                "success": True,
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address) if hasattr(network, "broadcast_address") else "N/A",
                "cidr": str(network),
                "first_host": first_host,
                "last_host": last_host,
                "total_addresses": num_addresses,
                "usable_hosts": usable_hosts
            }
        # Handle an exception raised by the preceding protected block.
        except ValueError as error:
            return {"success": False, "error": f"Invalid CIDR: {str(error)}"}

    # Parse comma-separated targets, such as 192.168.1.5,192.168.1.6, individually.
    if "," in target:
        parts = [p.strip() for p in target.split(",") if p.strip()]
        # Handle the branch where not parts evaluates to true.
        if not parts:
            return {"success": False, "error": "Empty target list."}
        
        total_ips = 0
        first_host = None
        last_host = None
        # Sum each subtarget's addresses and stop immediately if one is invalid.
        for p in parts:
            p_info = calculate_network(p)
            # Handle the branch where not p_info['success'] evaluates to true.
            if not p_info["success"]:
                return p_info
            total_ips += p_info["total_addresses"]
            # Handle the branch where not first_host evaluates to true.
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

    # Parse a short or fully qualified IP range, such as .10-40 or .10-192.168.1.40.
    if "-" in target:
        parts = target.split("-")
        # Handle the branch where len(parts) != 2 evaluates to true.
        if len(parts) != 2:
            return {"success": False, "error": "Invalid range format. Use e.g. 192.168.1.10-40"}
        
        start_part = parts[0].strip()
        end_part = parts[1].strip()

        # Run this block with structured exception handling.
        try:
            start_ip = ipaddress.IPv4Address(start_part)
            # Use a full end IP directly, or expand a final-octet shorthand from the start IP.
            if "." in end_part:
                end_ip = ipaddress.IPv4Address(end_part)
            # Handle the fallback branch when the preceding condition does not match.
            else:
                # Convert final-octet shorthand, such as 192.168.1.10-40, to a full IP.
                octets = start_part.split(".")
                # Handle the branch where len(octets) != 4 evaluates to true.
                if len(octets) != 4:
                    return {"success": False, "error": "Invalid start IP format."}
                octets[-1] = end_part
                end_ip_str = ".".join(octets)
                end_ip = ipaddress.IPv4Address(end_ip_str)

            # Reject reversed ranges before they produce invalid address counts.
            if start_ip > end_ip:
                return {"success": False, "error": "Start IP is greater than End IP in range."}

            num_ips = int(end_ip) - int(start_ip) + 1

            # Limit oversized ranges to prevent excessive resource consumption.
            if num_ips > 2048:
                return {
                    "success": False,
                    "error": "The selected range is too large. Maximum allowed size is 2048 IP addresses."
                }

            # Convert the range to a target format accepted by Nmap.
            start_octets = str(start_ip).split(".")
            end_octets = str(end_ip).split(".")
            # Handle the branch where start_octets[:3] == end_octets[:3] evaluates to true.
            if start_octets[:3] == end_octets[:3]:
                # Within the same /24, use Nmap's final-octet range form (for example, 10.0.0.1-20).
                nmap_target = f"{'.'.join(start_octets[:3])}.{start_octets[-1]}-{end_octets[-1]}"
            # Handle the fallback branch when the preceding condition does not match.
            else:
                # Across subnets, expand the range into a comma-separated list of addresses.
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
        # Handle an exception raised by the preceding protected block.
        except ValueError as error:
            return {"success": False, "error": f"Invalid range IP format: {str(error)}"}

    # Validate any input not matched above as a single IPv4 address.
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
    # Handle an exception raised by the preceding protected block.
    except ValueError as error:
        return {"success": False, "error": f"Invalid IP address format: {str(error)}"}


# Locate nmap executable.
def find_nmap_executable():
    """
    Finds the Nmap executable on Windows or through PATH.
    """

    # First, look for an Nmap executable registered in the operating system PATH.
    nmap_from_path = shutil.which("nmap")

    # Handle the branch where nmap_from_path evaluates to true.
    if nmap_from_path:
        return nmap_from_path

    # If it is not in PATH, try the common Windows installation directories.
    possible_paths = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe"
    ]

    # Iterate over possible_paths and bind each item to path.
    for path in possible_paths:
        # Handle the branch where os.path.exists(path) evaluates to true.
        if os.path.exists(path):
            return path

    return None


# Parse nmap xml.
def parse_nmap_xml(xml_output):
    """
    Parses Nmap XML output into structured scan data.
    """

    # Parse the XML root and convert each <host> node into a separate result record.
    parsed_hosts = []
    root = ET.fromstring(xml_output)

    # Iterate over root.findall('host') and bind each item to host.
    for host in root.findall("host"):
        # Read the host reachability state, defaulting to "unknown" when absent.
        status_element = host.find("status")
        host_status = status_element.get("state") if status_element is not None else "unknown"

        ip_address = "unknown"
        mac_address = ""
        mac_vendor = ""

        # Extract IPv4/IPv6 and, when available, MAC and vendor data from address nodes.
        for address_el in host.findall("address"):
            addr_type = address_el.get("addrtype", "")
            # Handle the branch where addr_type in ['ipv4', 'ipv6'] evaluates to true.
            if addr_type in ["ipv4", "ipv6"]:
                ip_address = address_el.get("addr", "unknown")
            # Handle the branch where addr_type == 'mac' evaluates to true.
            elif addr_type == "mac":
                mac_address = address_el.get("addr", "")
                mac_vendor = address_el.get("vendor", "")

        hostname = ""

        # Read the first hostname resolved by Nmap.
        hostnames_element = host.find("hostnames")
        # Handle the branch where hostnames_element is not None evaluates to true.
        if hostnames_element is not None:
            hostname_element = hostnames_element.find("hostname")
            # Handle the branch where hostname_element is not None evaluates to true.
            if hostname_element is not None:
                hostname = hostname_element.get("name", "")

        ports_data = []

        # Collect protocol, state, service, and version details for every port.
        ports_element = host.find("ports")
        # Handle the branch where ports_element is not None evaluates to true.
        if ports_element is not None:
            # Iterate over ports_element.findall('port') and bind each item to port.
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

                # If a service node exists, read its product and version fields safely.
                if service_element is not None:
                    service_name = service_element.get("name", "")
                    product = service_element.get("product", "")
                    version = service_element.get("version", "")
                    extra_info = service_element.get("extrainfo", "")

                # Collect the port's CPE strings for later vulnerability matching.
                cpe_list = []
                # Handle the branch where service_element is not None evaluates to true.
                if service_element is not None:
                    # Iterate over service_element.findall('cpe') and bind each item to cpe_el.
                    for cpe_el in service_element.findall("cpe"):
                        cpe_list.append(cpe_el.text or "")

                # Build the display version from nonempty product, version, and detail fields.
                version_display = " ".join(
                    item for item in [product, version, extra_info] if item
                )

                # Add the normalized port record to the host's port list.
                ports_data.append({
                    "port": port_number,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extra_info": extra_info,
                    "version_display": version_display if version_display else "-",
                    "cpe": cpe_list,
                })

        # If traceroute data exists, parse each route hop in order.
        trace_hops = []
        trace_element = host.find("trace")
        # Handle the branch where trace_element is not None evaluates to true.
        if trace_element is not None:
            # Iterate over trace_element.findall('hop') and bind each item to hop.
            for hop in trace_element.findall("hop"):
                trace_hops.append({
                    "hop": hop.get("ttl"),
                    "ipaddr": hop.get("ipaddr"),
                    "rtt": hop.get("rtt"),
                    "host": hop.get("host", "")
                })

        # Combine all parsed host fields into one result object.
        parsed_hosts.append({
            "address": ip_address,
            "mac_address": mac_address,
            "mac_vendor": mac_vendor,
            "hostname": hostname,
            "status": host_status,
            "ports": ports_data,
            "trace": trace_hops
        })

    return parsed_hosts


# Determine whether target vpn via nmap.
def is_target_vpn_via_nmap(target, nmap_executable):
    """
    Checks if any of the target IPs/subnets route through a VPN or virtual adapter
    using Nmap's language-independent interface list.
    """
    import socket
    import ipaddress
    import subprocess
    import re

    # Split comma-separated targets so each route can be checked independently.
    target_list = [t.strip() for t in target.split(",") if t.strip()]
    # Handle the branch where not target_list evaluates to true.
    if not target_list:
        return False

    # Retrieve Nmap's language-independent interface list once.
    nmap_interfaces = []
    # Run this block with structured exception handling.
    try:
        completed = subprocess.run(
            [nmap_executable, "--iflist"],
            capture_output=True,
            text=True,
            timeout=5
        )
        # Handle the branch where completed.returncode == 0 evaluates to true.
        if completed.returncode == 0:
            nmap_interfaces = completed.stdout.splitlines()
    # Handle an exception raised by the preceding protected block.
    except Exception:
        pass

    # Do not assume a VPN route when interface information cannot be retrieved.
    if not nmap_interfaces:
        return False

    # Iterate over target_list and bind each item to single_target.
    for single_target in target_list:
        # Select one representative test IP from a range or CIDR target.
        ip_to_test = None
        # Handle the branch where any((char in single_target for char in ['-', '*'])) evaluates to true.
        if any(char in single_target for char in ["-", "*"]):
            match = re.match(r'^([\d\.]+)', single_target)
            # Handle the branch where match evaluates to true.
            if match:
                ip_to_test = match.group(1)
        # Handle the fallback branch when the preceding condition does not match.
        else:
            # Run this block with structured exception handling.
            try:
                net = ipaddress.ip_network(single_target, strict=False)
                # Handle the branch where net.num_addresses > 1 evaluates to true.
                if net.num_addresses > 1:
                    ip_to_test = str(next(net.hosts()))
                # Handle the fallback branch when the preceding condition does not match.
                else:
                    ip_to_test = str(net.network_address)
            # Handle an exception raised by the preceding protected block.
            except ValueError:
                ip_to_test = single_target

        # Handle the branch where not ip_to_test evaluates to true.
        if not ip_to_test:
            continue

        # Use a UDP socket to discover which local IP the OS selects for this destination.
        local_ip = None
        # Run this block with structured exception handling.
        try:
            resolved_ip = socket.gethostbyname(ip_to_test)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((resolved_ip, 80))
            local_ip = s.getsockname()[0]
            s.close()
        # Handle an exception raised by the preceding protected block.
        except Exception:
            pass

        # Handle the branch where not local_ip evaluates to true.
        if not local_ip:
            continue

        # Check whether the local IP belongs to a VPN or tunnel interface in Nmap's list.
        for line in nmap_interfaces:
            # Handle the branch where local_ip in line evaluates to true.
            if local_ip in line:
                parts = line.split()
                # Handle the branch where len(parts) >= 3 evaluates to true.
                if len(parts) >= 3:
                    dev = parts[0].lower()
                    # A point-to-point type or a known tunnel device name indicates VPN use.
                    if "point2point" in line.lower() or any(kw in dev for kw in ["tun", "tap", "vpn", "ppp"]):
                        return True
                    
    return False


# Handle the discover active hosts operation.
def discover_active_hosts(target, timeout=0.4):
    """
    Performs a fast, parallel TCP connect-based host discovery on a target subnet in Python.
    Works reliably over VPNs and standard network interfaces without administrative privileges.
    """
    import socket
    import ipaddress
    import concurrent.futures
    import errno

    # Parse the target as a network; if parsing fails, treat it as one host.
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = list(net.hosts())
    # Handle an exception raised by the preceding protected block.
    except ValueError:
        return [target]

    # Avoid starting parallel discovery for a single host.
    if len(hosts) <= 1:
        return [target]

    # Probe common enterprise service ports to determine whether a host is active.
    common_ports = [80, 443, 22, 3389, 445, 135, 8080]
    active_hosts = []

    # Handle the probe host port operation.
    def probe_host_port(ip_str, port):
        # Attempt a connection to one TCP port with a short timeout.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip_str, port))
            s.close()
            # Both a successful connection and a refusal prove that the host responded.
            if result == 0 or result == errno.ECONNREFUSED:
                return True
        # Handle an exception raised by the preceding protected block.
        except Exception:
            pass
        return False

    # Check host status.
    def check_host_status(ip_str):
        # Probe common ports for a host and stop after the first positive response.
        for port in common_ports:
            # Handle the branch where probe_host_port(ip_str, port) evaluates to true.
            if probe_host_port(ip_str, port):
                return ip_str
        return None

    # Cap concurrent workers at 128 to avoid exhausting system resources.
    max_workers = min(128, len(hosts))
    # Manage concurrent.futures.ThreadPoolExecutor(max_workers=ma... within this scoped block.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_host_status, str(host)): str(host) for host in hosts}
        # Iterate over concurrent.futures.as_completed(futures) and bind each item to future.
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            # Handle the branch where res evaluates to true.
            if res:
                active_hosts.append(res)

    return active_hosts


# Handle the sanitize exclusion string operation.
def sanitize_exclusion_string(exclude_str):
    """
    Sanitizes and converts exclusion targets into Nmap-compatible format.
    Specifically, it converts hyphenated full IP ranges (e.g. 10.0.0.1-10.0.0.3)
    into Nmap-compatible octet suffix ranges (e.g. 10.0.0.1-3) or comma-separated lists.
    """
    # Convert an empty exclusion input directly to an empty Nmap argument.
    if not exclude_str:
        return ""
    
    sanitized_parts = []
    # Convert each comma-separated exclusion target to an Nmap-compatible form.
    parts = [p.strip() for p in exclude_str.split(",") if p.strip()]
    # Iterate over parts and bind each item to part.
    for part in parts:
        res = calculate_network(part)
        # Handle the branch where res['success'] evaluates to true.
        if res["success"]:
            sanitized_parts.append(res["cidr"])
        # Handle the fallback branch when the preceding condition does not match.
        else:
            # Preserve an unparsed value because it may be a valid hostname.
            sanitized_parts.append(part)
            
    return ",".join(sanitized_parts)


import threading

# Shared state that tracks running Nmap processes by scan and attempt identifiers.
active_processes = {}
active_process_attempt_tokens = {}
# Guard all shared process dictionaries with one lock to prevent race conditions.
active_processes_lock = threading.Lock()
active_scan_process_tokens = {}
# Allow a stalled Nmap process to run for at most ten minutes.
NMAP_SUBPROCESS_TIMEOUT_SECONDS = 600


# Group the state and behavior for StopResult.
@dataclass(frozen=True)
class StopResult:
    """Stores immutable permission and process outcomes for a stop request."""

    start_permission_revoked: bool
    had_processes: bool
    all_processes_stopped: bool

# Group the state and behavior for CompletedProcessDummy.
class CompletedProcessDummy:
    """Stores a Popen result in a lightweight CompletedProcess-like object."""

    # Handle the init operation.
    def __init__(self, returncode, stdout, stderr):
        # Store the subprocess return code and captured standard streams.
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

# Handle the allow scan process start operation.
def allow_scan_process_start(scan_id, process_token):
    """Allows a valid scan attempt token to start an Nmap process."""

    # Reject missing identifiers so process ownership always remains explicit.
    if scan_id is None or process_token is None:
        return False
    # Manage active_processes_lock within this scoped block.
    with active_processes_lock:
        # Reject a new attempt when a different token already owns the scan.
        existing_token = active_scan_process_tokens.get(scan_id)
        # Handle the branch where existing_token is not None and existing_token != process_token evaluates to true.
        if existing_token is not None and existing_token != process_token:
            return False
        active_scan_process_tokens[scan_id] = process_token
        return True


# Handle the end scan process attempt operation.
def end_scan_process_attempt(scan_id, process_token):
    """Revokes start permission only when the scan attempt owner matches."""

    # Handle the branch where scan_id is None or process_token is None evaluates to true.
    if scan_id is None or process_token is None:
        return
    # Manage active_processes_lock within this scoped block.
    with active_processes_lock:
        # Handle the branch where active_scan_process_tokens.get(scan_id) == process_token evaluates to true.
        if active_scan_process_tokens.get(scan_id) == process_token:
            active_scan_process_tokens.pop(scan_id, None)


# Handle the execute nmap subprocess operation.
def execute_nmap_subprocess(command, scan_id=None, process_token=None):
    """Starts Nmap, captures its output, and safely unregisters the process."""

    # Check permission and register Popen under one lock to avoid a stop/start race.
    with active_processes_lock:
        # Handle the branch where scan_id is not None and process_token is not None and (active_scan_process_tokens.get(scan_id) != process_t... evaluates to true.
        if (
            scan_id is not None
            and process_token is not None
            and active_scan_process_tokens.get(scan_id) != process_token
        ):
            return -1, "", "Scan attempt is no longer allowed to start Nmap."
        # Capture stdout and stderr as text so the XML result can be processed.
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # Register the process under its scan ID so it can be cancelled externally.
        if scan_id is not None:
            active_processes.setdefault(scan_id, set()).add(proc)
            active_process_attempt_tokens[proc] = process_token
    # Wait for completion; on timeout, kill the process and collect remaining output.
    try:
        stdout, stderr = proc.communicate(timeout=NMAP_SUBPROCESS_TIMEOUT_SECONDS)
        returncode = proc.returncode
    # Handle an exception raised by the preceding protected block.
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        returncode = -1
    # Run cleanup that must occur after the protected block.
    finally:
        # Remove process records regardless of success, failure, or timeout.
        if scan_id is not None:
            # Manage active_processes_lock within this scoped block.
            with active_processes_lock:
                processes = active_processes.get(scan_id)
                # Handle the branch where processes evaluates to true.
                if processes:
                    processes.discard(proc)
                    # Handle the branch where not processes evaluates to true.
                    if not processes:
                        active_processes.pop(scan_id, None)
                active_process_attempt_tokens.pop(proc, None)
    return returncode, stdout, stderr

# Handle the stop scan process operation.
def stop_scan_process(scan_id, process_token=None):
    """Stops processes for a scan or one attempt and reports the outcome."""

    # Select target processes and revoke start permission while holding the lock.
    with active_processes_lock:
        registered_token = active_scan_process_tokens.get(scan_id)
        all_registered_processes = list(active_processes.get(scan_id, set()))
        # When a token is supplied, leave processes from other attempts untouched.
        if process_token is not None:
            processes = [
                proc for proc in all_registered_processes
                if active_process_attempt_tokens.get(proc) == process_token
            ]
            # Handle the branch where registered_token != process_token and (not processes) evaluates to true.
            if registered_token != process_token and not processes:
                return StopResult(False, False, False)
        # Handle the fallback branch when the preceding condition does not match.
        else:
            processes = all_registered_processes
        start_permission_revoked = (
            registered_token is not None
            and (process_token is None or registered_token == process_token)
        )
        # Handle the branch where start_permission_revoked evaluates to true.
        if start_permission_revoked:
            active_scan_process_tokens.pop(scan_id, None)
    # With no running processes, report the permission revocation as a successful stop.
    if not processes:
        return StopResult(start_permission_revoked, False, True)

    all_stopped = True
    confirmed_stopped = []
    # Kill each process, wait briefly, and verify that it actually stopped.
    for proc in processes:
        # Run this block with structured exception handling.
        try:
            # Handle the branch where proc.poll() is None evaluates to true.
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            # Handle the branch where proc.poll() is None evaluates to true.
            if proc.poll() is None:
                all_stopped = False
            # Handle the fallback branch when the preceding condition does not match.
            else:
                confirmed_stopped.append(proc)
        # Handle an exception raised by the preceding protected block.
        except Exception:
            all_stopped = False

    # Remove only confirmed stopped processes from the shared registries.
    if confirmed_stopped:
        # Manage active_processes_lock within this scoped block.
        with active_processes_lock:
            registered = active_processes.get(scan_id)
            # Handle the branch where registered is not None evaluates to true.
            if registered is not None:
                registered.difference_update(confirmed_stopped)
                # Iterate over confirmed_stopped and bind each item to proc.
                for proc in confirmed_stopped:
                    active_process_attempt_tokens.pop(proc, None)
                # Handle the branch where not registered evaluates to true.
                if not registered:
                    active_processes.pop(scan_id, None)
    return StopResult(start_permission_revoked, True, all_stopped)


# Handle the extract scanned endpoints from xml operation.
def extract_scanned_endpoints_from_xml(xml_output):
    """Extracts every protocol/port pair described by Nmap scaninfo nodes."""

    # Return an empty collection when Nmap produced no XML output.
    endpoints = []
    # Handle the branch where not xml_output evaluates to true.
    if not xml_output:
        return endpoints
    # Parse each scaninfo node because TCP and UDP ranges may be listed separately.
    try:
        root = ET.fromstring(xml_output)
        # Iterate over root.findall('scaninfo') and bind each item to scaninfo.
        for scaninfo in root.findall("scaninfo"):
            protocol = scaninfo.get("protocol") or "tcp"
            services_str = scaninfo.get("services")
            # Expand the comma-separated services field into individual endpoints.
            if services_str:
                # Iterate over services_str.split(',') and bind each item to part.
                for part in services_str.split(","):
                    part = part.strip()
                    # Handle the branch where not part evaluates to true.
                    if not part:
                        continue
                    # Expand a port range, or append a single numeric port directly.
                    if "-" in part:
                        # Run this block with structured exception handling.
                        try:
                            start, end = part.split("-")
                            # Iterate over range(int(start), int(end) + 1) and bind each item to p.
                            for p in range(int(start), int(end) + 1):
                                endpoints.append((protocol.lower(), p))
                        # Ignore malformed service fragments without discarding valid ones.
                        except ValueError:
                            pass
                    # Handle the fallback branch when the preceding condition does not match.
                    else:
                        # Run this block with structured exception handling.
                        try:
                            endpoints.append((protocol.lower(), int(part)))
                        # Handle an exception raised by the preceding protected block.
                        except ValueError:
                            pass
    # Endpoint metadata is optional, so malformed XML yields an empty/partial list.
    except Exception:
        pass
    return endpoints


# Group the state and behavior for ScanOwnershipLost.
class ScanOwnershipLost(RuntimeError):
    """Signals that a worker no longer owns the scan it was executing."""

    pass


# Handle the notify scan progress operation.
def _notify_scan_progress(progress_callback, phase):
    """Reports a phase transition and aborts when the callback rejects ownership."""

    # A False callback result means another worker or cancellation now owns the scan.
    if progress_callback is not None and progress_callback(phase) is False:
        raise ScanOwnershipLost("Scan ownership was lost before the next scan phase.")


# Run nmap scan.
def run_nmap_scan(
    target,
    scan_type,
    ports=None,
    exclude_targets=None,
    timing_template="4",
    scan_id=None,
    progress_callback=None,
    process_token=None,
):
    """
    Runs an Nmap scan and returns structured results.
    """
    # Normalize exclusions before inserting them into the command line.
    if exclude_targets:
        exclude_targets = sanitize_exclusion_string(exclude_targets)

    # Resolve the executable once so every primary or fallback command uses the same binary.
    nmap_executable = find_nmap_executable()

    # Fail early with a user-facing message when Nmap is not installed.
    if not nmap_executable:
        return {
            "success": False,
            "command": "nmap",
            "output": "Nmap was not found. Please make sure Nmap is installed and added to PATH.",
            "hosts": []
        }

    # Map each supported scan type to its base Nmap flags.
    scan_configs = {
        "fast": ["-F"],
        "service_version": ["-sV", "-T4"],
        "ping_sweep": ["-sn"],
        "syn": ["-sS"],
        "connect": ["-sT"],
        "udp": ["-sU", "--top-ports", "100"],
        "aggressive": ["-A", "-T4"],
        "vuln": ["-sV", "-T4", "--script", "vuln"],
        # Keep legacy names compatible with existing stored scan definitions.
        "quick": ["-F"],
        "detailed": ["-sV", "-T4"]
    }

    # Reject unknown scan types before building or launching a command.
    if scan_type not in scan_configs:
        return {
            "success": False,
            "command": "Invalid scan type",
            "output": "Invalid scan type.",
            "hosts": []
        }

    # Copy flags so request-specific changes never mutate the shared configuration.
    flags = scan_configs[scan_type].copy()

    # Validate the timing template and fall back to Nmap's common T4 profile.
    if not timing_template or timing_template not in ["0", "1", "2", "3", "4", "5"]:
        timing_template = "4"

    # Replace an existing timing flag, or append one when the base profile has none.
    timing_flag = f"-T{timing_template}"
    has_replaced_timing = False
    # Iterate over enumerate(flags) and bind each item to (idx, flag).
    for idx, flag in enumerate(flags):
        # Handle the branch where flag.startswith('-T') and len(flag) == 3 and flag[2].isdigit() evaluates to true.
        if flag.startswith("-T") and len(flag) == 3 and flag[2].isdigit():
            flags[idx] = timing_flag
            has_replaced_timing = True
            break
    
    # Handle the branch where not has_replaced_timing evaluates to true.
    if not has_replaced_timing:
        flags.append(timing_flag)
    
    # Track fallback use so the response can explain the command adjustment.
    is_fallback = False
    original_command = None

    # On Windows, detect VPN routing before scanning through Nmap's interface list.
    is_vpn_detected = False
    # Handle the branch where os.name == 'nt' evaluates to true.
    if os.name == "nt":
        # Run this block with structured exception handling.
        try:
            is_vpn_detected = is_target_vpn_via_nmap(target, nmap_executable)
        # Handle an exception raised by the preceding protected block.
        except Exception:
            pass

    # Raw SYN/UDP scans can fail over virtual adapters, so switch to unprivileged TCP.
    if is_vpn_detected:
        adjusted_flags = []
        # Iterate over flags and bind each item to flag.
        for flag in flags:
            # Handle the branch where flag == '-sS' or flag == '-sU' evaluates to true.
            if flag == "-sS" or flag == "-sU":
                adjusted_flags.append("-sT")
            # Handle the fallback branch when the preceding condition does not match.
            else:
                adjusted_flags.append(flag)
        flags = adjusted_flags
        
        # Explicitly tell Nmap not to rely on raw-packet privileges.
        if "--unprivileged" not in flags:
            flags.append("--unprivileged")
            
        # Determine whether the VPN target is one host or a multi-address target.
        is_single_host = True
        # Handle the branch where any((char in target for char in ['-', ',', '*'])) evaluates to true.
        if any(char in target for char in ["-", ",", "*"]):
            is_single_host = False
        # Handle the fallback branch when the preceding condition does not match.
        else:
            # Run this block with structured exception handling.
            try:
                net = ipaddress.ip_network(target, strict=False)
                # Handle the branch where net.num_addresses > 1 evaluates to true.
                if net.num_addresses > 1:
                    is_single_host = False
            # Handle an exception raised by the preceding protected block.
            except ValueError:
                pass
        
        # Skip host discovery for a single VPN-routed host that may not answer probes.
        if is_single_host and "-Pn" not in flags:
            flags.append("-Pn")

        # Preserve the originally requested command for diagnostics in the response.
        is_fallback = True
        cmd_parts = [nmap_executable] + scan_configs[scan_type]
        # Handle the branch where ports and scan_type != 'ping_sweep' evaluates to true.
        if ports and scan_type != "ping_sweep":
            cmd_parts += ["-p", ports]
        # Handle the branch where exclude_targets evaluates to true.
        if exclude_targets:
            cmd_parts += ["--exclude", exclude_targets]
        cmd_parts += ["-oX", "-", target]
        original_command = " ".join(cmd_parts)

    # Custom ports override -F and --top-ports while preserving all other scan flags.
    if ports and scan_type != "ping_sweep":
        custom_flags = []
        skip_next = False
        # Iterate over flags and bind each item to flag.
        for flag in flags:
            # Handle the branch where skip_next evaluates to true.
            if skip_next:
                skip_next = False
                continue
            # Handle the branch where flag == '--top-ports' evaluates to true.
            if flag == "--top-ports":
                skip_next = True
                continue
            # Handle the branch where flag == '-F' evaluates to true.
            if flag == "-F":
                continue
            custom_flags.append(flag)
        command = [nmap_executable] + custom_flags + ["-p", ports]
    # Handle the fallback branch when the preceding condition does not match.
    else:
        command = [nmap_executable] + flags

    # Append sanitized exclusions only when the caller supplied them.
    if exclude_targets:
        command += ["--exclude", exclude_targets]

    # Request XML on stdout and place the target last in the final command.
    command += ["-oX", "-", target]

    # Execute the primary scan and wrap its streams in one consistent result object.
    try:
        _notify_scan_progress(progress_callback, "starting-primary-scan")
        returncode, stdout, stderr = execute_nmap_subprocess(command, scan_id, process_token)
        completed_process = CompletedProcessDummy(returncode, stdout, stderr)

        # Retry a failed SYN scan as TCP Connect when the error indicates missing privileges.
        if (
            scan_type == "syn"
            and completed_process.returncode != 0
            and any(err in (stderr + stdout).lower() for err in ["privilege", "permission denied", "dnet", "root", "socket-bind"])
        ):
            is_fallback = True
            original_command = " ".join(command)
            flags = scan_configs["connect"]
            
            # Rebuild the fallback command with the same custom ports and exclusions.
            if ports:
                command = [nmap_executable] + flags + ["-p", ports]
            # Handle the fallback branch when the preceding condition does not match.
            else:
                command = [nmap_executable] + flags

            # Handle the branch where exclude_targets evaluates to true.
            if exclude_targets:
                command += ["--exclude", exclude_targets]

            command += ["-oX", "-", target]

            # Report ownership immediately before launching the privilege fallback.
            _notify_scan_progress(progress_callback, "starting-privilege-fallback-scan")
            returncode_fb, stdout_fb, stderr_fb = execute_nmap_subprocess(command, scan_id, process_token)
            completed_process = CompletedProcessDummy(returncode_fb, stdout_fb, stderr_fb)
            stdout = completed_process.stdout
            stderr = completed_process.stderr

        # Parse host and scanned-endpoint data only when XML output is available.
        hosts = []
        scanned_endpoints = []

        # Handle the branch where stdout evaluates to true.
        if stdout:
            hosts = parse_nmap_xml(stdout)
            scanned_endpoints = extract_scanned_endpoints_from_xml(stdout)

        # Determine whether empty results belong to one host or an entire subnet.
        is_single_host = True
        # Handle the branch where any((char in target for char in ['-', ',', '*'])) evaluates to true.
        if any(char in target for char in ["-", ",", "*"]):
            is_single_host = False
        # Handle the fallback branch when the preceding condition does not match.
        else:
            # Run this block with structured exception handling.
            try:
                net = ipaddress.ip_network(target, strict=False)
                # Handle the branch where net.num_addresses > 1 evaluates to true.
                if net.num_addresses > 1:
                    is_single_host = False
            # Handle an exception raised by the preceding protected block.
            except ValueError:
                pass

        # A successful scan with no hosts may mean Npcap raw probes failed on a VPN adapter.
        # Retry with socket-based, unprivileged TCP logic appropriate to the target size.
        if completed_process.returncode == 0 and len(hosts) == 0:
            # For one host, replace raw scan flags and force scanning without discovery.
            if is_single_host:
                fallback_command = []
                # Iterate over command[:-1] and bind each item to arg.
                for arg in command[:-1]:
                    # Handle the branch where arg == '-sS' or arg == '-sU' evaluates to true.
                    if arg == "-sS" or arg == "-sU":
                        fallback_command.append("-sT")
                    # Handle the fallback branch when the preceding condition does not match.
                    else:
                        fallback_command.append(arg)
                fallback_command.append(target)
                
                # Handle the branch where '--unprivileged' not in fallback_command evaluates to true.
                if "--unprivileged" not in fallback_command:
                    fallback_command.append("--unprivileged")
                # Handle the branch where '-Pn' not in fallback_command evaluates to true.
                if "-Pn" not in fallback_command:
                    fallback_command.append("-Pn")
                
                # Launch the single-host fallback and adopt it only when it finds hosts.
                try:
                    _notify_scan_progress(progress_callback, "starting-single-host-fallback-scan")
                    retcode, f_stdout, f_stderr = execute_nmap_subprocess(fallback_command, scan_id, process_token)
                    fallback_process = CompletedProcessDummy(retcode, f_stdout, f_stderr)
                    
                    # Handle the branch where fallback_process.returncode == 0 evaluates to true.
                    if fallback_process.returncode == 0:
                        fallback_stdout = fallback_process.stdout
                        # Handle the branch where fallback_stdout evaluates to true.
                        if fallback_stdout:
                            fallback_hosts = parse_nmap_xml(fallback_stdout)
                            # Handle the branch where len(fallback_hosts) > 0 evaluates to true.
                            if len(fallback_hosts) > 0:
                                completed_process = fallback_process
                                stdout = fallback_stdout
                                stderr = fallback_process.stderr
                                hosts = fallback_hosts
                                scanned_endpoints = extract_scanned_endpoints_from_xml(fallback_stdout)
                                is_fallback = True
                                original_command = " ".join(command)
                                command = fallback_command
                # Ownership loss must stop the workflow; ordinary scan failures are nonfatal here.
                except ScanOwnershipLost:
                    raise
                # Handle an exception raised by the preceding protected block.
                except (OSError, ValueError, subprocess.SubprocessError, ET.ParseError):
                    pass
            # Handle the fallback branch when the preceding condition does not match.
            else:
                # For a subnet, discover responsive hosts in Python before retrying Nmap.
                try:
                    _notify_scan_progress(progress_callback, "starting-host-discovery")
                    active_ips = discover_active_hosts(target)
                    _notify_scan_progress(progress_callback, "completed-host-discovery")
                    # Scan only responsive IPs to avoid a slow unprivileged pass over the full subnet.
                    if active_ips:
                        target_list = ",".join(active_ips)
                        fallback_command = []
                        # Iterate over command[:-1] and bind each item to arg.
                        for arg in command[:-1]:
                            # Handle the branch where arg == '-sS' or arg == '-sU' evaluates to true.
                            if arg == "-sS" or arg == "-sU":
                                fallback_command.append("-sT")
                            # Handle the fallback branch when the preceding condition does not match.
                            else:
                                fallback_command.append(arg)
                        fallback_command.append(target_list)
                        
                        # Handle the branch where '--unprivileged' not in fallback_command evaluates to true.
                        if "--unprivileged" not in fallback_command:
                            fallback_command.append("--unprivileged")
                        # Handle the branch where '-Pn' not in fallback_command evaluates to true.
                        if "-Pn" not in fallback_command:
                            fallback_command.append("-Pn")
                            
                        # Launch the subnet fallback only while this worker still owns the scan.
                        _notify_scan_progress(progress_callback, "starting-subnet-fallback-scan")
                        retcode, f_stdout, f_stderr = execute_nmap_subprocess(fallback_command, scan_id, process_token)
                        fallback_process = CompletedProcessDummy(retcode, f_stdout, f_stderr)
                        
                        # Handle the branch where fallback_process.returncode == 0 evaluates to true.
                        if fallback_process.returncode == 0:
                            fallback_stdout = fallback_process.stdout
                            # Handle the branch where fallback_stdout evaluates to true.
                            if fallback_stdout:
                                fallback_hosts = parse_nmap_xml(fallback_stdout)
                                # Handle the branch where len(fallback_hosts) > 0 evaluates to true.
                                if len(fallback_hosts) > 0:
                                    completed_process = fallback_process
                                    stdout = fallback_stdout
                                    stderr = fallback_process.stderr
                                    hosts = fallback_hosts
                                    scanned_endpoints = extract_scanned_endpoints_from_xml(fallback_stdout)
                                    is_fallback = True
                                    original_command = " ".join(command)
                                    command = fallback_command
                # Propagate cancellation/ownership loss while tolerating fallback-specific errors.
                except ScanOwnershipLost:
                    raise
                # Handle an exception raised by the preceding protected block.
                except (OSError, ValueError, subprocess.SubprocessError, ET.ParseError):
                    pass

        # Add a diagnostic note when the executed command differs from the requested one.
        final_output = stderr if stderr else ""
        # Handle the branch where is_fallback evaluates to true.
        if is_fallback:
            # Handle the branch where original_command evaluates to true.
            if original_command:
                fallback_note = f"[INFO] VPN/Virtual Adapter or privilege issue detected. Automatically fell back to unprivileged scan.\n[Original Command]: {original_command}\n\n"
            # Handle the fallback branch when the preceding condition does not match.
            else:
                fallback_note = "[INFO] SYN scan requires administrative privileges. Automatically fell back to TCP Connect scan (-sT).\n"
            final_output = fallback_note + final_output

        # Return one normalized result shape for successful and failed Nmap exits.
        return {
            "success": completed_process.returncode == 0,
            "command": " ".join(command),
            "output": final_output,
            "hosts": hosts,
            "scanned_endpoints": scanned_endpoints
        }

    # Ownership loss is a control-flow signal that the caller must handle directly.
    except ScanOwnershipLost:
        raise

    # Convert invalid Nmap XML into a structured scan failure.
    except ET.ParseError as error:
        return {
            "success": False,
            "command": " ".join(command),
            "output": f"Failed to parse Nmap XML output: {str(error)}",
            "hosts": [],
            "scanned_endpoints": []
        }

    # Convert subprocess timeouts into a user-facing structured failure.
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": " ".join(command),
            "output": "The scan timed out. The target network may be too large or unreachable.",
            "hosts": [],
            "scanned_endpoints": []
        }

    # Keep unexpected execution errors inside the standard response contract.
    except Exception as error:
        return {
            "success": False,
            "command": " ".join(command),
            "output": f"Unexpected error: {str(error)}",
            "hosts": [],
            "scanned_endpoints": []
        }
    
# Determine whether ip allowed.
def is_ip_allowed(ip_str):
    """
    Helper to check if a single IP address belongs to the allowed private/loopback/link-local scopes.
    """
    # Treat absent optional addresses as harmless because there is nothing to scan.
    if not ip_str or ip_str == "N/A":
        return True
    # Accept only private, loopback, or link-local address objects.
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    # Any unparsable value fails the allowlist check.
    except ValueError:
        return False

# Determine whether target safe.
def is_target_safe(target_str):
    """
    Safely verifies if all IP addresses in the target string are allowed (private/loopback/link-local).
    Iteratively parses comma-separated lists and hyphenated ranges without recursion.
    """
    # Empty targets are never valid scan destinations.
    if not target_str:
        return False

    # Split comma-separated targets and process them iteratively.
    sub_targets = [p.strip() for p in target_str.split(",") if p.strip()]
    # Handle the branch where not sub_targets evaluates to true.
    if not sub_targets:
        return False

    # Every component must pass; one unsafe component rejects the complete request.
    for target in sub_targets:
        # Validate a short or fully qualified hyphenated IP range.
        if "-" in target:
            parts = target.split("-")
            # Exactly one separator is required for a valid start/end range.
            if len(parts) != 2:
                return False
            start_part = parts[0].strip()
            end_part = parts[1].strip()
            
            # Handle the branch where not start_part evaluates to true.
            if not start_part:
                return False

            # Expand final-octet shorthand, such as 192.168.1.10-40.
            if "." not in end_part:
                dots = start_part.split(".")
                # Handle the branch where len(dots) == 4 evaluates to true.
                if len(dots) == 4:
                    end_part = f"{dots[0]}.{dots[1]}.{dots[2]}.{end_part}"
                # Handle the fallback branch when the preceding condition does not match.
                else:
                    return False
            
            # Both boundaries must remain inside the permitted address scopes.
            if not is_ip_allowed(start_part) or not is_ip_allowed(end_part):
                return False

        # Otherwise, validate the component as CIDR notation or a single IP address.
        else:
            # Run this block with structured exception handling.
            try:
                network = ipaddress.ip_network(target, strict=False)
                # Explicitly reject special-purpose networks before checking local scopes.
                if network.is_multicast or network.is_unspecified or network.is_reserved:
                    return False
                # Handle the branch where not (network.is_private or network.is_loopback or network.is_link_local) evaluates to true.
                if not (network.is_private or network.is_loopback or network.is_link_local):
                    return False
            # Hostnames and malformed network strings are not permitted scan targets.
            except ValueError:
                return False

    return True

# Validate scan target.
def validate_scan_target(network_info, scan_type):
    """
    Validates whether the calculated network is safe and reasonable to scan.
    """

    # Apply scan-type-specific size limits before any Nmap process is started.
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
            # Keep limits for legacy scan names used by older records.
            "quick": 1024,
            "detailed": 256
        }

        max_allowed_addresses = max_addresses_by_scan_type.get(scan_type)

        # Reject scan types that do not have an explicit safety limit.
        if max_allowed_addresses is None:
            return {
                "success": False,
                "error": "Invalid scan type selected."
            }

        # Default to one address for older or minimal network-info dictionaries.
        total_addresses = network_info.get("total_addresses", 1)

        # Prevent expensive scan profiles from running against oversized networks.
        if total_addresses > max_allowed_addresses:
            return {
                "success": False,
                "error": (
                    f"The selected network is too large for {scan_type} scan. "
                    f"Maximum allowed size is {max_allowed_addresses} IP addresses."
                )
            }

        # Restrict scanning to private, loopback, and link-local destinations.
        if not is_target_safe(network_info.get("cidr")):
            return {
                "success": False,
                "error": "Only private, loopback, or link-local networks are allowed to be scanned."
            }

        # The target is both within the size limit and inside an allowed address scope.
        return {"success": True, "error": None}

    # Preserve the validation response shape if unexpected input data raises an error.
    except Exception as error:
        return {
            "success": False,
            "error": str(error)
        }
