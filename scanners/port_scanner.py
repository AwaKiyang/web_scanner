import nmap

def scan_ports(target):
    nm = nmap.PortScanner()
    result = []

    try:
        nm.scan(hosts=target, arguments='-T4 -F')  # Fast scan
        host = nm.all_hosts()[0]

        result.append(f"Host: {host}")
        result.append(f"Status: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                result.append(f"Port {port}/{proto} - {state}")

    except Exception as e:
        result.append(f"Error: {str(e)}")

    return result
