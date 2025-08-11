import nmap
import ipaddress

def scan_ip_range(ip_range, ports='1-1024'):
    nm = nmap.PortScanner()

    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        print(f"Invalid IP range: {e}")
        return

    print(f"\n[*] Scanning IP range: {ip_range} for open ports ({ports})\n")

    for ip in network.hosts():
        ip = str(ip)
        try:
            print(f"[+] Scanning {ip}...")
            nm.scan(hosts=ip, arguments=f"-p {ports} --open")
            if ip in nm.all_hosts():
                print(f"    - Host: {ip} ({nm[ip].hostname()})")
                print(f"    - State: {nm[ip].state()}")
                for proto in nm[ip].all_protocols():
                    ports = nm[ip][proto].keys()
                    for port in sorted(ports):
                        state = nm[ip][proto][port]['state']
                        name = nm[ip][proto][port]['name']
                        print(f"      Port: {port}/tcp | State: {state} | Service: {name}")
            else:
                print(f"    - No open ports found.")
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

if __name__ == "__main__":
    # Example usage
    ip_range_input = input("Enter IP range (e.g., 192.168.1.0/24): ")
    port_range_input = input("Enter port range to scan (default 1-1024): ") or "1-1024"
    scan_ip_range(ip_range_input, port_range_input)
