"""Shared, evidence-based device classification for scans and topology."""

from collections import defaultdict


MIN_CLASSIFICATION_SCORE = 4


# Handle the contains any operation.
def _contains_any(text, keywords):
    return any(keyword in text for keyword in keywords)


# Handle the normalise evidence operation.
def _normalise_evidence(hostname, vendor, ports_list):
    open_ports = set()
    service_evidence = []

    # Iterate over ports_list or [] and bind each item to port_info.
    for port_info in ports_list or []:
        # Handle the branch where not isinstance(port_info, dict) evaluates to true.
        if not isinstance(port_info, dict):
            # Run this block with structured exception handling.
            try:
                open_ports.add(int(port_info))
            # Handle an exception raised by the preceding protected block.
            except (TypeError, ValueError):
                continue
            continue

        state = str(port_info.get("state") or "").lower()
        # Handle the branch where state and state != 'open' evaluates to true.
        if state and state != "open":
            continue
        # Run this block with structured exception handling.
        try:
            port = int(port_info.get("port"))
        # Handle an exception raised by the preceding protected block.
        except (TypeError, ValueError):
            port = None
        # Handle the branch where port evaluates to true.
        if port:
            open_ports.add(port)

        # Iterate over ('service', 'product', 'version', 'extra_info') and bind each item to field.
        for field in ("service", "product", "version", "extra_info"):
            value = port_info.get(field)
            # Handle the branch where value evaluates to true.
            if value:
                service_evidence.append(str(value).lower())
        cpe_values = port_info.get("cpe") or []
        # Handle the branch where isinstance(cpe_values, str) evaluates to true.
        if isinstance(cpe_values, str):
            cpe_values = [cpe_values]
        service_evidence.extend(str(value).lower() for value in cpe_values if value)

    return (
        (hostname or "").lower(),
        (vendor or "").lower(),
        open_ports,
        " ".join(service_evidence),
    )


# Handle the classify device type operation.
def classify_device_type(hostname, vendor, ports_list, *, is_gateway=False):
    """Classify a device using weighted identity, service, and port evidence."""
    # Handle the branch where is_gateway evaluates to true.
    if is_gateway:
        return "Router"

    hostname, vendor, ports, services = _normalise_evidence(
        hostname,
        vendor,
        ports_list,
    )
    identity = f"{hostname} {vendor} {services}"
    scores = defaultdict(int)

    # Handle the add operation.
    def add(device_type, points, condition):
        # Handle the branch where condition evaluates to true.
        if condition:
            scores[device_type] += points

    add("Firewall", 10, _contains_any(identity, (
        "firewall", "fortigate", "fortinet", "pfsense", "opnsense",
        "checkpoint", "sonicwall", "watchguard", "sophos", "pan-os",
        "palo alto",
    )))

    add("IP Phone", 9, _contains_any(identity, (
        "ip phone", "voip", "yealink", "grandstream", "snom", "fanvil",
        "polycom", "gigaset", "avaya phone", "sip phone",
    )))
    add("IP Phone", 6, bool(ports & {2000, 5060, 5061}))

    add("IP Camera", 9, _contains_any(identity, (
        "camera", "cctv", "webcam", "hikvision", "dahua", "foscam",
        "reolink", "amcrest", "hanwha", "axis communications", "ipcam",
    )))
    add("IP Camera", 6, 554 in ports or "rtsp" in services)

    add("Virtual Machine", 9, _contains_any(identity, (
        "vmware", "virtualbox", "qemu", "proxmox", "xen", "hyper-v",
        "kvm virtual", "virtual machine",
    )))
    add("Virtual Machine", 7, _contains_any(hostname, ("vm-", "-vm", "virtual-")))

    router_vendors = (
        "zte", "linksys", "netgear", "tp-link", "d-link", "tenda",
        "zyxel", "mikrotik", "ubiquiti", "huawei", "cambium", "ruckus",
        "arris", "technicolor", "sagemcom", "motorola solutions",
    )
    network_vendors = router_vendors + (
        "cisco", "juniper", "aruba", "arista", "extreme networks",
        "hewlett packard enterprise",
    )
    add("Router", 8, _contains_any(hostname, (
        "router", "gateway", "modem", "-gw", "gw-", "-rt", "rt-", "ont",
    )))
    add("Router", 5, _contains_any(vendor, router_vendors))
    add("Router", 6, _contains_any(services, (
        "routeros", "openwrt", "dd-wrt", "dnsmasq", "home gateway",
        "broadband router",
    )))
    add("Router", 4, bool(ports & {67, 68, 179, 520}))
    add("Router", 3, 53 in ports)

    add("Switch", 9, _contains_any(hostname, (
        "switch", "sw-", "-sw", "catalyst", "procurve", "edgeswitch",
    )))
    add("Switch", 6, "switch" in services)
    add("Switch", 2, _contains_any(vendor, network_vendors))
    add("Switch", 3, bool(ports & {161, 162}) or "snmp" in services)

    add("Printer", 9, _contains_any(identity, (
        "printer", "copier", "epson", "canon", "lexmark", "brother",
        "xerox", "konica", "ricoh", "kyocera", "okidata", "laserjet",
    )))
    add("Printer", 7, bool(ports & {515, 631, 9100}))

    add("IoT", 8, _contains_any(hostname, (
        "iot", "smart", "chromecast", "smart-tv", "smarttv", "raspberry",
    )))
    add("IoT", 7, bool(ports & {1883, 8883}) or "mqtt" in services)

    add("Server", 8, _contains_any(hostname, (
        "server", "srv-", "-srv", "domain-controller", "dc-", "nas-",
    )))
    add("Server", 8, _contains_any(vendor, ("synology", "qnap")))
    add("Server", 6, bool(ports & {
        25, 110, 143, 389, 465, 587, 636, 993, 995, 1433, 1521, 2049,
        3306, 5432, 6379, 27017,
    }))
    add("Server", 5, _contains_any(services, (
        "mysql", "postgresql", "mariadb", "mongodb", "redis", "ldap",
        "domain controller", "exchange", "dovecot", "postfix", "nfs",
    )))

    add("Workstation", 9, _contains_any(hostname, (
        "workstation", "desktop", "laptop", "win10", "win11", "client-",
        "-pc", "pc-",
    )))
    add("Workstation", 4, bool(ports & {139, 445, 3389}))
    add("Workstation", 3, _contains_any(services, (
        "microsoft-ds", "netbios-ssn", "remote desktop", "windows",
    )))

    add("Mobile", 8, _contains_any(hostname, (
        "iphone", "ipad", "android", "galaxy", "pixel-", "mobile",
    )))
    add("Mobile", 4, _contains_any(services, ("android", "iphone os", "ios device")))

    # Handle the branch where not scores evaluates to true.
    if not scores:
        return "Unknown"

    priority = (
        "Firewall", "IP Phone", "IP Camera", "Printer", "Virtual Machine",
        "Router", "Switch", "Server", "Workstation", "IoT", "Mobile",
    )
    best_score = max(scores.values())
    # Handle the branch where best_score < MIN_CLASSIFICATION_SCORE evaluates to true.
    if best_score < MIN_CLASSIFICATION_SCORE:
        return "Unknown"
    return next(device_type for device_type in priority if scores[device_type] == best_score)
