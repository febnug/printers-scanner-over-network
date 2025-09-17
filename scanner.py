#!/usr/bin/env python3
# Scan printers in WiFi LAN, show MAC + Vendor
import ipaddress
import socket
import fcntl, struct
import psutil
import subprocess
import csv
import re
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PRINTER_PORTS = {
    631: "IPP",
    9100: "RAW JetDirect",
    515: "LPD"
}

OUI_CACHE = Path.home() / ".cache" / "oui.txt"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

def get_iface_and_subnet():
    gws = psutil.net_if_addrs()
    for iface, addrs in gws.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return iface, f"{addr.address}/{addr.netmask}"
    raise RuntimeError("No active interface found.")

def iface_to_subnet(iface):
    addrs = psutil.net_if_addrs()[iface]
    for addr in addrs:
        if addr.family == socket.AF_INET:
            return ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
    raise RuntimeError("No subnet found for iface")

def mac_lookup():
    """Parse OUI database into dict {OUI: Vendor}"""
    if not OUI_CACHE.exists():
        try:
            OUI_CACHE.parent.mkdir(parents=True, exist_ok=True)
            print("OUI database not found locally, attempting to download...")
            urllib.request.urlretrieve(OUI_URL, OUI_CACHE)
            print(f"OUI database downloaded to {OUI_CACHE}")
        except Exception as e:
            print(f"Could not download OUI DB: {e}")
            return {}
    vendors = {}
    try:
        with open(OUI_CACHE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) >= 2:
                        prefix = parts[0].strip().replace("-", ":").upper()
                        vendor = parts[1].strip()
                        vendors[prefix] = vendor
    except Exception as e:
        print(f"Failed to parse OUI DB: {e}")
    return vendors

def get_mac(ip):
    try:
        pid = subprocess.Popen(["ip", "neigh", "show", ip],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, _ = pid.communicate(timeout=2)
        out = out.decode()
        m = re.search(r"lladdr\s+([0-9a-f:]{17})", out)
        if m:
            return m.group(1).lower()
    except Exception:
        return None
    return None

def get_vendor(mac, vendors):
    if not mac:
        return ""
    prefix = mac.upper()[0:8]
    return vendors.get(prefix, "")

def check_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        if port in (9100, 631):
            try:
                data = s.recv(64)
                return True, data.decode(errors="ignore").strip()
            except Exception:
                return True, ""
        return True, ""
    except Exception:
        return False, ""
    finally:
        try:
            s.close()
        except Exception:
            pass

def scan_host(ip, vendors):
    open_ports = []
    banners = {}
    for port in PRINTER_PORTS.keys():
        ok, banner = check_port(ip, port)
        if ok:
            open_ports.append(str(port))
            if banner:
                banners[port] = banner
    if not open_ports:
        return None

    mac = get_mac(ip)
    vendor = get_vendor(mac, vendors)
    return {
        "ip": ip,
        "mac": mac or "",
        "vendor": vendor,
        "ports": ",".join(open_ports),
        "banner": banners.get(9100) or banners.get(631) or ""
    }

def main():
    iface, _ = get_iface_and_subnet()
    subnet = iface_to_subnet(iface)
    print(f"Detected interface: {iface}  subnet: {subnet}")

    # Load OUI database
    vendors = mac_lookup()
    if not vendors:
        print("Vendor lookup disabled (no OUI DB).")

    hosts = [str(ip) for ip in subnet.network.hosts()]
    print(f"Starting scan of {len(hosts)} addresses with 200 workers...")

    results = []
    with ThreadPoolExecutor(max_workers=200) as ex:
        futs = {ex.submit(scan_host, ip, vendors): ip for ip in hosts}
        for f in as_completed(futs):
            r = f.result()
            if r:
                results.append(r)

    print(f"Scan finished, found {len(results)} potential printers.\n")

    print("Results:")
    print("-" * 140)
    print(f"{'IP':<16} {'MAC':<18} {'Vendor':<30} {'Ports':<12} Banner")
    print("-" * 140)
    for r in results:
        print(f"{r['ip']:<16} {r['mac']:<18} {r['vendor']:<30} {r['ports']:<12} {r['banner'][:60]}")
    print("-" * 140)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = f"printer_scan_{ts}.csv"
    with open(outfile, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP", "MAC", "Vendor", "Ports", "Banner"])
        for r in results:
            w.writerow([r["ip"], r["mac"], r["vendor"], r["ports"], r["banner"]])
    print(f"Results saved to {outfile}")

if __name__ == "__main__":
    main()
