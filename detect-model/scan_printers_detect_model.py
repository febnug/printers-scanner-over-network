#!/usr/bin/env python3
"""
scan_printers_detect_model.py

Scan LAN for printers, detect MAC/vendor, attempt SNMP (via snmpget) and HTTP/IPP/banner,
and extract printer model/type into a "Model" column.

Usage:
    python3 scan_printers_detect_model.py
    python3 scan_printers_detect_model.py 192.168.1.0/24

Requires:
 - snmpget available (net-snmp)
 - requests (for HTTP probing): pip install requests
"""
from __future__ import annotations
import ipaddress, socket, subprocess, urllib.request, os, csv, time, sys, re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests  # pip install requests

# ------------- settings -------------
PRINTER_PORTS = [631, 9100, 515]
SNMP_PORT = 161
PING_CMD = ["ping", "-c", "1", "-W", "1"]
WORKERS_PING = 120
WORKERS_SCAN = 120
TCP_TIMEOUT = 0.9
OUI_CACHE = Path.home() / ".cache" / "oui.txt"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

SNMP_COMMUNITIES = ["public", "private", "community", "brother", "hp", "admin"]
# Extend OIDs to include extra descriptive fields
SNMP_OIDS = [
    "1.3.6.1.2.1.1.1.0",         # sysDescr
    "1.3.6.1.2.1.25.3.2.1.3.1",  # hrDeviceDescr
    "1.3.6.1.2.1.43.5.1.1.16.1", # prtGeneralPrinterName
    "1.3.6.1.2.1.43.5.1.1.17.1", # prtGeneralSerialNumber
]

SNMPGET_TIMEOUT = 3
IP_NEIGH_TIMEOUT = 1

# ------------- helpers -------------
def run_cmd_capture(cmd: List[str], timeout: float = 3) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return p.returncode, p.stdout.decode(errors="ignore"), p.stderr.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def detect_iface_and_cidr() -> Tuple[Optional[str], Optional[str]]:
    try:
        rc, out, _ = run_cmd_capture(["ip", "route", "get", "8.8.8.8"], timeout=1.0)
        if rc == 0 and out:
            parts = out.split()
            dev = None; src = None
            for i, p in enumerate(parts):
                if p == "dev" and i+1 < len(parts): dev = parts[i+1]
                if p == "src" and i+1 < len(parts): src = parts[i+1]
            if dev:
                rc2, out2, _ = run_cmd_capture(["ip","-o","-f","inet","addr","show","dev",dev], timeout=0.8)
                if rc2 == 0 and out2:
                    for line in out2.splitlines():
                        toks = line.split()
                        if "inet" in toks:
                            cidr = toks[toks.index("inet")+1]; return dev, cidr
                if src:
                    return dev, src + "/24"
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        local_ip = s.getsockname()[0]; s.close(); return None, f"{local_ip}/24"
    except Exception:
        return None, None

def ensure_oui_db(local_path: Path = OUI_CACHE, url: str = OUI_URL) -> Dict[str,str]:
    m: Dict[str,str] = {}
    if not local_path.exists():
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            print("OUI DB not found locally, attempting to download...")
            urllib.request.urlretrieve(url, str(local_path))
            print("Downloaded OUI DB to", local_path)
        except Exception as e:
            print("Could not download OUI DB:", e)
            return {}
    try:
        with open(local_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) >= 2:
                        prefix = parts[0].strip().replace("-", ":").upper()
                        vendor = parts[1].strip()
                        prefix = ":".join(p.strip() for p in prefix.split(":")[:3])
                        m[prefix] = vendor
    except Exception as e:
        print("Failed to parse OUI DB:", e)
    return m

def ping_host(ip: str) -> bool:
    try:
        subprocess.run(PING_CMD + [ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return True
    except Exception:
        return False

def get_mac_from_arp(ip: str) -> Optional[str]:
    try:
        with open("/proc/net/arp","r") as fh:
            for line in fh.readlines()[1:]:
                fields = line.split()
                if len(fields) >= 4 and fields[0] == ip and fields[3] != "00:00:00:00:00:00":
                    return fields[3].lower()
    except Exception:
        pass
    rc, out, _ = run_cmd_capture(["ip","neigh","show", ip], timeout=IP_NEIGH_TIMEOUT)
    if rc == 0 and out:
        m = re.search(r"lladdr\s+([0-9a-f:]{17})", out, re.IGNORECASE)
        if m: return m.group(1).lower()
    return None

def vendor_from_mac(mac: Optional[str], oui_map: Dict[str,str]) -> str:
    if not mac: return ""
    cleaned = mac.upper()
    prefix = ":".join(cleaned.split(":")[0:3])
    return oui_map.get(prefix, "")

def tcp_port_open(ip: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout); s.connect((ip, port)); s.close(); return True
    except Exception: return False

def udp_probe(ip: str, port: int, timeout: float = 0.6) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
        s.sendto(b"\x00", (ip, port))
        try: s.recvfrom(1024); s.close(); return True
        except Exception: s.close(); return False
    except Exception: return False

def snmpget_single(ip: str, community: str, oid: str, timeout: int = SNMPGET_TIMEOUT) -> Optional[str]:
    cmd = ["snmpget", "-v1", "-c", community, "-t", str(max(1, timeout)), "-r", "0", ip, oid]
    rc, out, err = run_cmd_capture(cmd, timeout=timeout+1)
    if rc != 0 or not out:
        return None
    if "=" in out:
        val = out.split("=",1)[1].strip()
        m = re.search(r'(?:[A-Z0-9\-\_]+\s*:\s*)?["\']?(.*)["\']?\s*$', val)
        if m: return m.group(1).strip()
        return val
    return None

def snmp_try_communities(ip: str, communities: List[str], oids: List[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Try communities and OIDs. Return (community, oid, value) on first success.
    """
    for comm in communities:
        for oid in oids:
            val = snmpget_single(ip, comm, oid, timeout=SNMPGET_TIMEOUT)
            if val:
                return comm, oid, val
    return None, None, None

def http_probe_model(ip: str) -> Optional[str]:
    """If HTTP or IPP (port 631) responds, fetch / and try to parse <title> or 'model' text."""
    urls = [f"http://{ip}/", f"http://{ip}:631/"]
    for u in urls:
        try:
            r = requests.get(u, timeout=2)
            if r.status_code == 200 and r.text:
                # title
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE|re.DOTALL)
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()
                    # try extract model-like token from title
                    mod = extract_model_from_strings([title])
                    if mod: return mod
                    return title
                # fallback search for words like 'Model' or 'Printer'
                m2 = re.search(r"(Model[:\s]*[A-Za-z0-9\-\s]+)", r.text, re.IGNORECASE)
                if m2:
                    return re.sub(r"\s+", " ", m2.group(1)).strip()
        except Exception:
            continue
    return None

def grab_9100_banner_raw(ip: str) -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        s.connect((ip, 9100))
        s.sendall(b"\r\n")
        data = s.recv(512)
        s.close()
        if data:
            return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return None


# ------------- model extraction heuristics -------------
VENDORS = ["Brother","HP","Hewlett-Packard","Canon","Epson","Xerox","Kyocera","Ricoh","Samsung","Konica","Sharp","Lexmark","OKI","Fuji","Pantum"]

# heuristic regex to find model tokens: words with letters and digits, maybe dash/slash, length 2..30
MODEL_RE = re.compile(r"\b([A-Za-z]{2,10}[- ]?[A-Za-z]*\d[\w\-\/]*)\b")

def extract_model_from_strings(strs: List[str]) -> Optional[str]:
    """Try to find a likely model string from provided strings (sysDescr, banners, titles)."""
    candidates: List[Tuple[int,str]] = []
    for s in strs:
        if not s: continue
        # common: brand followed by model in sysDescr, try to find brand near token
        for v in VENDORS:
            if v.lower() in s.lower():
                # find token with digits after vendor
                m = re.search(rf"{re.escape(v)}[,:\-]?\s*([A-Za-z0-9\-\s\/]+)", s, re.IGNORECASE)
                if m:
                    token = m.group(1).strip()
                    token = re.sub(r"\s{2,}", " ", token)
                    token = token.split(",")[0]
                    return f"{v} {token}"
        # if above not found, use generic regex to find model-like words
        for mm in MODEL_RE.findall(s):
            mm_clean = mm.strip().strip(",;\"'")
            # deprioritize purely alphabetic tokens
            if re.search(r"\d", mm_clean):
                candidates.append( (len(mm_clean), mm_clean) )
    if candidates:
        # prefer shorter tokens (likely model identifiers)
        candidates.sort(key=lambda x: x[0])
        return candidates[0][1]
    return None

# -------------- per-host scan --------------
def scan_host(ip: str, oui_map: Dict[str,str], snmp_communities: List[str], snmp_oids: List[str]) -> Optional[Dict]:
    open_ports = []
    for p in PRINTER_PORTS:
        if tcp_port_open(ip, p, timeout=0.8):
            open_ports.append(p)
    udp161 = udp_probe(ip, SNMP_PORT, timeout=0.5)
    if not open_ports and not udp161:
        return None

    mac = get_mac_from_arp(ip)
    vendor = vendor_from_mac(mac, oui_map)

    # collect candidate strings
    candidate_strings: List[str] = []

    # try SNMP for a few oids (stop on first success but collect multiple if possible)
    comm_used, oid_used, snmp_val = snmp_try_communities(ip, snmp_communities, snmp_oids)
    if snmp_val:
        candidate_strings.append(snmp_val)

    # try more OIDs individually to append additional info (no need to stop)
    for oid in snmp_oids:
        if oid == oid_used: continue
        v = snmpget_single(ip, comm_used or snmp_communities[0], oid, timeout=1) if comm_used else None
        if v:
            candidate_strings.append(v)

    # try HTTP/IPP for model/title
    if 631 in open_ports or 80 in open_ports:
        http_model = http_probe_model(ip)
        if http_model:
            candidate_strings.append(http_model)

    # try 9100 banner
    if 9100 in open_ports:
        b = grab_9100_banner_raw(ip)
        if b:
            candidate_strings.append(b)

    # extract model from all candidate strings
    model = extract_model_from_strings(candidate_strings)

    return {
        "ip": ip,
        "mac": mac or "",
        "vendor": vendor,
        "ports": ",".join(map(str,open_ports)),
        "udp161": udp161,
        "snmp_comm": comm_used or "",
        "snmp_oid": oid_used or "",
        "snmp_val": snmp_val or "",
        "model": model or "",
    }

# --------------- main ----------------
def main():
    args = sys.argv[1:]
    manual_cidr = args[0] if args else None

    iface, cidr = detect_iface_and_cidr()
    if manual_cidr:
        cidr = manual_cidr
    if cidr is None:
        print("Failed to detect network. Provide CIDR as arg.")
        sys.exit(1)

    print(f"Detected interface: {iface or '(unknown)'}  subnet: {cidr}")
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]

    oui_map = ensure_oui_db()
    if oui_map:
        print(f"OUI DB loaded: {len(oui_map)} entries")
    else:
        print("OUI DB unavailable — vendor lookup disabled")

    print(f"Pinging {len(hosts)} hosts to populate ARP (concurrency={WORKERS_PING})...")
    t_ping = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS_PING) as ex:
        futures = [ex.submit(ping_host, h) for h in hosts]
        for _ in as_completed(futures):
            pass
    print(f"Ping stage done in {time.time() - t_ping:.1f}s")

    print(f"Scanning {len(hosts)} hosts (concurrency={WORKERS_SCAN})...")
    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS_SCAN) as ex:
        futs = {ex.submit(scan_host, h, oui_map, SNMP_COMMUNITIES, SNMP_OIDS): h for h in hosts}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if r:
                    results.append(r)
            except Exception:
                pass
    print(f"Scan finished in {time.time() - t0:.1f}s")

    # print summary
    print("\nResults (printer-like or SNMP responsive):")
    print("-" * 140)
    print(f"{'IP':16} {'MAC':18} {'Vendor':24} {'Model':28} {'Ports':8} {'UDP161':6} {'SNMP_comm'}")
    print("-" * 140)
    for r in sorted(results, key=lambda x: tuple(map(int, x["ip"].split('.')))):
        print(f"{r['ip']:16} {r['mac']:18} {r['vendor'][:24]:24} {r['model'][:28]:28} {r['ports']:8} {str(r['udp161']):6} {r['snmp_comm']}")
    print("-" * 140)

    # save CSV
    csvname = f"printer_scan_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(csvname, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip","mac","vendor","model","ports","udp161","snmp_comm","snmp_val","snmp_oid"])
        for r in results:
            w.writerow([r["ip"], r["mac"], r["vendor"], r["model"], r["ports"], r["udp161"], r["snmp_comm"], r.get("snmp_val",""), r.get("snmp_oid","")])
    print("Results saved to", csvname)

if __name__ == "__main__":
    main()
