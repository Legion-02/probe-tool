import socket
import requests
import argparse

# -------- Subdomain Enumeration --------
def subdomain_enum(domain, wordlist):
    found = []
    with open(wordlist, "r") as f:
        for line in f:
            sub = line.strip()
            url = f"http://{sub}.{domain}"
            try:
                requests.get(url, timeout=2)
                print(f"[+] Found subdomain: {url}")
                found.append(url)
            except requests.ConnectionError:
                pass
    return found

# -------- Port Scanning --------
def port_scan(host, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"[+] Port {port} open on {host}")
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

# -------- Directory Brute Force --------
def dir_brute_force(url, wordlist):
    found = []
    with open(wordlist, "r") as f:
        for line in f:
            directory = line.strip()
            target = f"{url}/{directory}"
            r = requests.get(target)
            if r.status_code == 200:
                print(f"[+] Found directory: {target}")
                found.append(target)
    return found

# -------- Banner Grabbing --------
def banner_grab(host, port):
    try:
        s = socket.socket()
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode().strip()
        print(f"[+] Banner on {host}:{port}:\n{banner}\n")
        return banner
    except:
        return None

# -------- Main --------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Probe Tool - Simple Reconnaissance Utility")
    parser.add_argument("--domain", help="Target domain for subdomain scan")
    parser.add_argument("--host", help="Target host for port scan/banner grabbing")
    parser.add_argument("--url", help="Target URL for directory brute force")
    parser.add_argument("--sub-wordlist", default="wordlists/subs.txt")
    parser.add_argument("--dir-wordlist", default="wordlists/dirs.txt")
    args = parser.parse_args()

    if args.domain:
        subdomain_enum(args.domain, args.sub_wordlist)

    if args.host:
        common_ports = [21, 22, 80, 443, 3306, 8080]
        open_ports = port_scan(args.host, common_ports)
        for port in open_ports:
            banner_grab(args.host, port)

    if args.url:
        dir_brute_force(args.url, args.dir_wordlist)
