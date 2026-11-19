import csv
import json
import socket
import subprocess
import ipaddress
import sys
import time
from pathlib import Path
from datetime import datetime
from collections import Counter

import psutil


# ============================================================
# NETWORK SECURITY ANALYZER v3.0
# Defensive local computer edition
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

TARGET = "127.0.0.1"
PORTS_TO_SCAN = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 27017
]
TIMEOUT = 0.4
MONITOR_INTERVAL = 5


def run_powershell(command):
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=20, errors="replace"
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return result.stderr.strip() or result.stdout.strip() or "Tidak dapat membaca konfigurasi."
    except subprocess.TimeoutExpired:
        return "PowerShell timeout."
    except Exception as error:
        return f"Gagal menjalankan PowerShell: {error}"


def scan_local_ports():
    print("\n[1] PEMERIKSAAN PORT LOCALHOST")
    results = []
    for port in PORTS_TO_SCAN:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        try:
            status = "OPEN" if sock.connect_ex((TARGET, port)) == 0 else "CLOSED"
        except OSError:
            status = "ERROR"
        finally:
            sock.close()
        results.append({"host": TARGET, "port": port, "status": status})
        print(f"Port {port:<6} : {status}")
    return results


def get_process_name(pid):
    if pid in (None, 0, ""):
        return "Unknown"
    try:
        return psutil.Process(int(pid)).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError, TypeError):
        return "Unknown"


def get_process_path(pid):
    if pid in (None, 0, ""):
        return "Unknown"
    try:
        return psutil.Process(int(pid)).exe() or "Unknown"
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError, TypeError):
        return "Unknown"


def is_loopback(address):
    try:
        return ipaddress.ip_address(str(address).split("%")[0]).is_loopback
    except ValueError:
        return False


def classify_ip(address):
    try:
        ip = ipaddress.ip_address(str(address).split("%")[0])
        if ip.is_loopback:
            return "LOOPBACK"
        if ip.is_private:
            return "PRIVATE"
        if ip.is_global:
            return "PUBLIC"
        return "OTHER"
    except ValueError:
        return "UNKNOWN"


def get_risk(port, addresses):
    normalized = [str(address).split("%")[0] for address in addresses]
    if normalized and all(is_loopback(address) for address in normalized):
        return "LOW", "Hanya menerima koneksi dari komputer sendiri"

    high_ports = {
        3306: "MySQL terikat ke antarmuka jaringan; periksa kebutuhan akses",
        445: "SMB; pastikan akses masuk dibatasi oleh Windows Firewall",
        3389: "RDP; pastikan hanya dapat diakses pihak berwenang",
        5900: "VNC; periksa autentikasi dan pembatasan akses",
        6379: "Redis; periksa autentikasi dan pembatasan akses",
        27017: "MongoDB; periksa autentikasi dan pembatasan akses"
    }
    if port in high_ports:
        return "HIGH", high_ports[port]
    if port == 139:
        return "REVIEW", "NetBIOS; periksa apakah layanan ini diperlukan"
    if port == 21:
        return "REVIEW", "FTP; periksa kebutuhan dan keamanan layanan"
    if port == 23:
        return "HIGH", "Telnet tidak mengenkripsi komunikasi"
    if port in (80, 443, 8080, 8443):
        return "INFO", "Layanan web; pastikan layanan yang aktif memang diperlukan"
    if port == 135 or 49664 <= port <= 49685:
        return "INFO", "Layanan RPC Windows; bukan otomatis kerentanan"
    if port in (623, 16992):
        return "REVIEW", "Periksa layanan manajemen perangkat"
    return "REVIEW", "Periksa identitas layanan dan kebutuhan akses jaringan"


def get_listening_services():
    print("\n[2] PEMERIKSAAN LAYANAN LISTENING")
    grouped = {}
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Akses ditolak. Coba jalankan terminal sebagai Administrator.")
        return []
    except Exception as error:
        print(f"Gagal membaca socket: {error}")
        return []

    for connection in connections:
        if connection.status != psutil.CONN_LISTEN or not connection.laddr:
            continue
        pid = connection.pid
        port = connection.laddr.port
        address = connection.laddr.ip
        process_name = get_process_name(pid)
        key = (pid, port, process_name)
        grouped.setdefault(key, {
            "pid": pid if pid is not None else "",
            "process": process_name,
            "port": port,
            "addresses": set()
        })
        grouped[key]["addresses"].add(address)

    results = []
    for item in grouped.values():
        addresses = sorted(item["addresses"])
        risk, reason = get_risk(item["port"], addresses)
        result = {
            "pid": item["pid"], "process": item["process"],
            "port": item["port"], "addresses": ", ".join(addresses),
            "risk": risk, "reason": reason
        }
        results.append(result)
        print(f"{result['process']:<22} PID: {str(result['pid']):<7} "
              f"Port: {result['port']:<6} Risk: {risk:<7} IP: {result['addresses']}")
    return sorted(results, key=lambda item: item["port"])


def get_connection_assessment(state, remote_type, pid, process_name):
    state = str(state).upper()
    if state in ("TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"):
        return "INFO", "Koneksi sedang/baru saja ditutup"
    if state == "LISTEN":
        return "INFO", "Socket menunggu koneksi masuk"
    if pid in (None, 0, "") or process_name == "Unknown":
        return "REVIEW", "Identitas proses tidak tersedia; verifikasi jika berulang"
    if remote_type == "LOOPBACK":
        return "LOW", "Koneksi hanya pada komputer sendiri"
    if remote_type == "PRIVATE":
        return "INFO", "Koneksi ke jaringan privat; pastikan perangkat dikenal"
    if remote_type == "PUBLIC":
        return "INFO", "Koneksi ke IP publik; bukan otomatis berbahaya"
    return "REVIEW", "Jenis alamat tujuan tidak dapat dipastikan"


def get_active_connections(verbose=True):
    if verbose:
        print("\n[3] PEMERIKSAAN KONEKSI AKTIF")
    results, seen = [], set()
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Akses ditolak. Coba jalankan terminal sebagai Administrator.")
        return []
    except Exception as error:
        print(f"Gagal membaca koneksi aktif: {error}")
        return []

    for connection in connections:
        if not connection.raddr:
            continue
        local_ip = connection.laddr.ip if connection.laddr else ""
        local_port = connection.laddr.port if connection.laddr else ""
        remote_ip = connection.raddr.ip
        remote_port = connection.raddr.port
        state = connection.status
        key = (connection.pid, local_ip, local_port, remote_ip, remote_port, state)
        if key in seen:
            continue
        seen.add(key)

        pid = connection.pid
        process_name = get_process_name(pid)
        remote_type = classify_ip(remote_ip)
        risk, reason = get_connection_assessment(state, remote_type, pid, process_name)
        result = {
            "pid": pid if pid is not None else "",
            "process": process_name,
            "local_address": f"{local_ip}:{local_port}",
            "remote_address": f"{remote_ip}:{remote_port}",
            "remote_type": remote_type,
            "state": state,
            "risk": risk,
            "reason": reason
        }
        results.append(result)
        if verbose:
            print(f"{process_name:<20} PID: {str(result['pid']):<7} "
                  f"{result['local_address']} -> {result['remote_address']} "
                  f"| {state:<12} | {risk}")
    if verbose and not results:
        print("Tidak ditemukan koneksi dengan alamat tujuan.")
    return sorted(results, key=lambda item: (
        {"HIGH": 0, "REVIEW": 1, "INFO": 2, "LOW": 3}.get(item["risk"], 4),
        item["process"]
    ))


def check_firewall():
    print("\n[4] PEMERIKSAAN WINDOWS FIREWALL")
    output = run_powershell("netsh advfirewall show allprofiles state")
    states = []
    for line in output.splitlines():
        if "State" in line:
            state = line.split()[-1].upper()
            if state in ("ON", "OFF"):
                states.append(state)
    if states and all(state == "ON" for state in states):
        status = "ON - Semua profil yang terbaca aktif"
    elif states and any(state == "OFF" for state in states):
        status = "WARNING - Ada profil firewall nonaktif"
    else:
        status = "UNKNOWN - Status tidak dapat dipastikan"
    print(status)
    return status, output


def check_smb():
    print("\n[5] PEMERIKSAAN SMB")
    command = ("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, "
               "EnableSMB2Protocol | ConvertTo-Json -Compress")
    output = run_powershell(command)
    try:
        data = json.loads(output)
        smb1, smb2 = data.get("EnableSMB1Protocol", "Unknown"), data.get("EnableSMB2Protocol", "Unknown")
        print(f"SMB1: {smb1}\nSMB2: {smb2}")
        return {"smb1": str(smb1), "smb2": str(smb2), "raw": output}
    except Exception:
        print("Tidak dapat membaca konfigurasi SMB.\n" + output)
        return {"smb1": "Unknown", "smb2": "Unknown", "raw": output}


def normalize_network_category(category):
    mapping = {
        "0": "Public", "1": "Private", "2": "DomainAuthenticated",
        "PUBLIC": "Public", "PRIVATE": "Private",
        "DOMAINAUTHENTICATED": "DomainAuthenticated"
    }
    return mapping.get(str(category).upper(), str(category))


def check_network_profile():
    print("\n[6] PEMERIKSAAN PROFIL JARINGAN")
    command = ("Get-NetConnectionProfile | Select-Object InterfaceAlias, "
               "NetworkCategory | ConvertTo-Json -Compress")
    output = run_powershell(command)
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]
        profiles = []
        for item in data:
            alias = item.get("InterfaceAlias", "Unknown")
            raw = item.get("NetworkCategory", "Unknown")
            category = normalize_network_category(raw)
            profiles.append({"interface": alias, "category": category, "raw_category": str(raw)})
            print(f"Interface: {alias} | Profil: {category}")
        if not profiles:
            print("Tidak ada profil jaringan yang terbaca.")
        return profiles
    except Exception:
        print("Tidak dapat membaca profil jaringan.\n" + output)
        return []


def check_file_signature(file_path):
    path = Path(file_path)
    if not path.exists():
        return "FILE NOT FOUND"
    safe_path = str(path).replace("'", "''")
    output = run_powershell(f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}').Status")
    return output.strip() or "UNKNOWN"


def find_lms_processes():
    matches = []
    for process in psutil.process_iter(["pid", "name", "exe"]):
        try:
            if (process.info.get("name") or "").lower() == "lms.exe":
                matches.append({"pid": process.info.get("pid"), "path": process.info.get("exe") or ""})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return matches


def check_xampp_services(services):
    print("\n[7] PEMERIKSAAN APACHE DAN MYSQL")
    apache = [item for item in services if item["process"].lower() == "httpd.exe"]
    mysql = [item for item in services if item["process"].lower() in ("mysqld.exe", "mariadbd.exe")]
    apache_status = "TERDETEKSI" if apache else "TIDAK TERDETEKSI"
    mysql_status = "TERDETEKSI" if mysql else "TIDAK TERDETEKSI"
    print(f"Apache (httpd.exe): {apache_status}")
    print(f"MySQL             : {mysql_status}")
    for item in apache + mysql:
        print(f"  {item['process']} | Port {item['port']} | {item['addresses']} | {item['risk']}")
    return {
        "apache_status": apache_status, "mysql_status": mysql_status,
        "apache_details": apache, "mysql_details": mysql
    }


def check_lms_signatures():
    print("\n[8] PEMERIKSAAN TANDA TANGAN DIGITAL LMS")
    processes = find_lms_processes()
    if not processes:
        print("LMS.exe tidak sedang berjalan; pemeriksaan dilewati.")
        return [{"pid": "", "path": "", "signature": "PROCESS NOT RUNNING"}]
    results = []
    for item in processes:
        path = item["path"]
        status = check_file_signature(path) if path else "PATH UNAVAILABLE"
        results.append({"pid": item["pid"], "path": path, "signature": status})
        print(f"PID: {item['pid']} | File: {path or 'Unknown'} | Signature: {status}")
    return results


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def save_reports(port_results, services, active_connections, firewall,
                 firewall_raw, smb, profiles, xampp, signatures, now):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    txt_path = REPORT_DIR / f"security_report_{timestamp}.txt"
    lines = [
        "NETWORK SECURITY ANALYZER v3.0", "=" * 70,
        f"Waktu pemeriksaan: {now.isoformat(timespec='seconds')}",
        f"Target port scan: {TARGET}", "", "PORT SCAN LOCALHOST", "-" * 70
    ]
    lines += [f"Port {x['port']}: {x['status']}" for x in port_results]
    lines += ["", "LISTENING SERVICES", "-" * 70]
    for x in services:
        lines.append(f"PID: {x['pid']} | Proses: {x['process']} | Port: {x['port']} | "
                     f"IP: {x['addresses']} | Risk: {x['risk']} | {x['reason']}")
    lines += ["", "ACTIVE CONNECTIONS", "-" * 70]
    for x in active_connections:
        lines.append(f"PID: {x['pid']} | {x['process']} | {x['local_address']} -> "
                     f"{x['remote_address']} | {x['remote_type']} | {x['state']} | "
                     f"{x['risk']} | {x['reason']}")
    lines += ["", "WINDOWS FIREWALL", firewall, firewall_raw,
              "", "SMB CONFIGURATION", f"SMB1: {smb['smb1']}", f"SMB2: {smb['smb2']}",
              "", "NETWORK PROFILES"]
    lines += [f"{x['interface']}: {x['category']}" for x in profiles]
    lines += ["", "XAMPP SERVICES", f"Apache: {xampp['apache_status']}",
              f"MySQL: {xampp['mysql_status']}", "", "DIGITAL SIGNATURES"]
    lines += [f"PID: {x['pid']} | Path: {x['path']} | Signature: {x['signature']}" for x in signatures]
    lines += ["", "CATATAN ANALISIS",
              "Label risiko adalah pemeriksaan awal, bukan bukti kompromi.",
              "Koneksi ke IP publik tidak otomatis berarti berbahaya.",
              "Port listening belum tentu dapat diakses dari internet.",
              "Firewall memfilter lalu lintas; listener dapat tetap terlihat."]
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    write_csv(REPORT_DIR / f"port_scan_{timestamp}.csv", port_results, ["host", "port", "status"])
    write_csv(REPORT_DIR / f"listening_services_{timestamp}.csv", services,
              ["pid", "process", "port", "addresses", "risk", "reason"])
    write_csv(REPORT_DIR / f"active_connections_{timestamp}.csv", active_connections,
              ["pid", "process", "local_address", "remote_address", "remote_type", "state", "risk", "reason"])
    write_csv(REPORT_DIR / f"digital_signatures_{timestamp}.csv", signatures,
              ["pid", "path", "signature"])
    print("\n[9] LAPORAN BERHASIL DISIMPAN")
    print("Folder laporan:", REPORT_DIR)
    print("Laporan TXT:", txt_path)


def connection_snapshot():
    """Membuat snapshot koneksi TCP yang memiliki alamat tujuan."""
    snapshot = {}
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError) as error:
        print(f"Tidak dapat membaca koneksi TCP: {error}")
        return snapshot

    for conn in connections:
        if not conn.raddr:
            continue
        local_ip = conn.laddr.ip if conn.laddr else ""
        local_port = conn.laddr.port if conn.laddr else ""
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        pid = conn.pid if conn.pid is not None else ""
        process = get_process_name(pid)
        # Status tidak dimasukkan ke key agar perubahan status socket
        # tidak keliru dianggap sebagai koneksi baru.
        key = (pid, local_ip, local_port, remote_ip, remote_port)
        snapshot[key] = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "pid": pid,
            "process": process,
            "local_address": f"{local_ip}:{local_port}",
            "remote_address": f"{remote_ip}:{remote_port}",
            "remote_type": classify_ip(remote_ip),
            "state": conn.status
        }
    return snapshot


def monitor_network_changes():
    """Mendeteksi koneksi baru dan koneksi yang hilang pada komputer sendiri."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = REPORT_DIR / f"network_changes_{timestamp}.csv"
    fields = ["timestamp", "event", "pid", "process", "local_address",
              "remote_address", "remote_type", "state"]

    print("=" * 70)
    print("       NETWORK SECURITY ANALYZER v3.0 - NETWORK MONITOR")
    print("=" * 70)
    print(f"Interval pemantauan : {MONITOR_INTERVAL} detik")
    print("Target              : koneksi TCP komputer sendiri")
    print("Hentikan            : CTRL + C")
    print("Mempersiapkan baseline koneksi...")

    previous = connection_snapshot()
    print(f"Baseline tersimpan: {len(previous)} koneksi")
    print(f"Log perubahan: {csv_path}")
    print("-" * 70)

    event_count = Counter()
    try:
        with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            while True:
                time.sleep(MONITOR_INTERVAL)
                current = connection_snapshot()
                new_keys = current.keys() - previous.keys()
                ended_keys = previous.keys() - current.keys()

                for key in new_keys:
                    item = current[key].copy()
                    item["event"] = "NEW_CONNECTION"
                    item["timestamp"] = datetime.now().isoformat(timespec="seconds")
                    writer.writerow(item)
                    file.flush()
                    event_count["NEW_CONNECTION"] += 1
                    print(f"[BARU] {item['process']} | {item['local_address']} -> "
                          f"{item['remote_address']} | {item['state']}")

                for key in ended_keys:
                    item = previous[key].copy()
                    item["event"] = "CONNECTION_ENDED"
                    item["timestamp"] = datetime.now().isoformat(timespec="seconds")
                    writer.writerow(item)
                    file.flush()
                    event_count["CONNECTION_ENDED"] += 1
                    print(f"[PUTUS] {item['process']} | {item['local_address']} -> "
                          f"{item['remote_address']}")

                if not new_keys and not ended_keys:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                          f"Tidak ada perubahan | Koneksi terpantau: {len(current)}")
                previous = current

    except KeyboardInterrupt:
        print("\nMonitoring dihentikan oleh pengguna.")
    finally:
        print("\nRINGKASAN MONITORING")
        print("Koneksi baru       :", event_count["NEW_CONNECTION"])
        print("Koneksi terputus   :", event_count["CONNECTION_ENDED"])
        print("File log           :", csv_path)


def main():
    now = datetime.now()
    print("=" * 70)
    print("                 NETWORK SECURITY ANALYZER v3.0")
    print("                 DEFENSIVE LOCALHOST EDITION")
    print("=" * 70)

    port_results = scan_local_ports()
    services = get_listening_services()
    active_connections = get_active_connections()
    firewall, firewall_raw = check_firewall()
    smb = check_smb()
    profiles = check_network_profile()
    xampp = check_xampp_services(services)
    signatures = check_lms_signatures()

    save_reports(port_results, services, active_connections, firewall,
                 firewall_raw, smb, profiles, xampp, signatures, now)

    high_listening = sum(x["risk"] == "HIGH" for x in services)
    review_listening = sum(x["risk"] == "REVIEW" for x in services)
    review_connections = sum(x["risk"] == "REVIEW" for x in active_connections)
    time_wait_count = sum(str(x["state"]).upper() == "TIME_WAIT" for x in active_connections)
    public_established = sum(
        x["remote_type"] == "PUBLIC" and str(x["state"]).upper() == "ESTABLISHED"
        for x in active_connections
    )

    print("\n" + "=" * 70)
    print("ANALISIS SELESAI")
    print("Jumlah port diperiksa          :", len(port_results))
    print("Jumlah layanan listening       :", len(services))
    print("Jumlah koneksi terinventarisasi:", len(active_connections))
    print("HIGH (listening)               :", high_listening)
    print("REVIEW (listening)             :", review_listening)
    print("REVIEW (koneksi)               :", review_connections)
    print("Koneksi TIME_WAIT              :", time_wait_count)
    print("Koneksi PUBLIC ESTABLISHED     :", public_established)
    print("Windows Firewall               :", firewall)
    print("SMB1                           :", smb["smb1"])
    print("SMB2                           :", smb["smb2"])
    print("=" * 70)


if __name__ == "__main__":
    if "--monitor" in sys.argv:
        monitor_network_changes()
    else:
        main()
