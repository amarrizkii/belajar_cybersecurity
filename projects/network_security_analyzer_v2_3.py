import csv
import json
import socket
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime

import psutil


# ============================================================
# NETWORK SECURITY ANALYZER v2.3
# Pemeriksaan defensif komputer sendiri (localhost)
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


def run_powershell(command):
    """Menjalankan PowerShell untuk membaca konfigurasi Windows."""
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command", command
            ],
            capture_output=True,
            text=True,
            timeout=20,
            errors="replace"
        )

        if result.returncode == 0:
            return result.stdout.strip()

        return result.stderr.strip() or result.stdout.strip() or (
            "Tidak dapat membaca konfigurasi."
        )
    except subprocess.TimeoutExpired:
        return "PowerShell timeout."
    except Exception as error:
        return f"Gagal menjalankan PowerShell: {error}"


def scan_local_ports():
    """Memeriksa port TCP pada localhost, bukan komputer lain."""
    print("\n[1] PEMERIKSAAN PORT LOCALHOST")
    results = []

    for port in PORTS_TO_SCAN:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        try:
            status_code = sock.connect_ex((TARGET, port))
            status = "OPEN" if status_code == 0 else "CLOSED"
        except OSError:
            status = "ERROR"
        finally:
            sock.close()

        results.append({
            "host": TARGET,
            "port": port,
            "status": status
        })
        print(f"Port {port:<6} : {status}")

    return results


def get_process_name(pid):
    """Mengambil nama proses berdasarkan PID."""
    if pid in (None, 0, ""):
        return "Unknown"

    try:
        return psutil.Process(int(pid)).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied,
            psutil.ZombieProcess, ValueError, TypeError):
        return "Unknown"


def get_process_path(pid):
    """Mengambil lokasi executable proses jika dapat diakses."""
    if pid in (None, 0, ""):
        return "Unknown"

    try:
        return psutil.Process(int(pid)).exe() or "Unknown"
    except (psutil.NoSuchProcess, psutil.AccessDenied,
            psutil.ZombieProcess, ValueError, TypeError):
        return "Unknown"


def is_loopback(address):
    """Memeriksa apakah alamat IP merupakan loopback."""
    try:
        return ipaddress.ip_address(str(address).split("%")[0]).is_loopback
    except ValueError:
        return False


def classify_ip(address):
    """Mengelompokkan IP; kategori PUBLIC bukan berarti berbahaya."""
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
    """Penilaian awal layanan listening berdasarkan port dan binding."""
    normalized = [str(address).split("%")[0] for address in addresses]

    loopback_only = bool(normalized) and all(
        is_loopback(address) for address in normalized
    )

    if loopback_only:
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
    """Mengambil socket LISTEN dan menggabungkan IPv4/IPv6 yang sama."""
    print("\n[2] PEMERIKSAAN LAYANAN LISTENING")
    grouped = {}

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Akses ditolak. Jalankan PowerShell/VS Code sebagai Administrator.")
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

        if key not in grouped:
            grouped[key] = {
                "pid": pid if pid is not None else "",
                "process": process_name,
                "port": port,
                "addresses": set()
            }

        grouped[key]["addresses"].add(address)

    results = []
    for item in grouped.values():
        addresses = sorted(item["addresses"])
        risk, reason = get_risk(item["port"], addresses)

        result = {
            "pid": item["pid"],
            "process": item["process"],
            "port": item["port"],
            "addresses": ", ".join(addresses),
            "risk": risk,
            "reason": reason
        }
        results.append(result)

        print(
            f"{result['process']:<22} "
            f"PID: {str(result['pid']):<7} "
            f"Port: {result['port']:<6} "
            f"Risk: {risk:<7} "
            f"IP: {result['addresses']}"
        )

    return sorted(results, key=lambda item: item["port"])


def get_connection_assessment(state, remote_type, pid, process_name):
    """Menilai koneksi tanpa menganggap IP publik otomatis berbahaya."""
    normalized_state = str(state).upper()

    if normalized_state == "TIME_WAIT":
        return "INFO", "Koneksi sedang/baru saja ditutup; bukan bukti ancaman"

    if normalized_state == "CLOSE_WAIT":
        return "INFO", "Koneksi menunggu aplikasi menutup socket"

    if normalized_state in ("FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"):
        return "INFO", "Koneksi berada dalam proses penutupan"

    if normalized_state == "LISTEN":
        return "INFO", "Socket sedang menunggu koneksi masuk"

    if pid in (None, 0, "") or process_name == "Unknown":
        return "REVIEW", "Identitas proses tidak tersedia; verifikasi jika berulang"

    if remote_type == "LOOPBACK":
        return "LOW", "Koneksi hanya pada komputer sendiri"

    if remote_type == "PRIVATE":
        return "INFO", "Koneksi ke jaringan privat; pastikan perangkat tujuan dikenal"

    if remote_type == "PUBLIC":
        if normalized_state == "ESTABLISHED":
            return "INFO", (
                "Koneksi ke IP publik; periksa aplikasi dan tujuan jika tidak dikenal"
            )
        return "INFO", "Alamat tujuan publik; status koneksi perlu dilihat bersama konteks"

    return "REVIEW", "Jenis alamat tujuan tidak dapat dipastikan"


def get_active_connections():
    """Menginventarisasi koneksi jaringan komputer sendiri."""
    print("\n[3] PEMERIKSAAN KONEKSI AKTIF")
    results = []
    seen = set()

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Akses ditolak. Jalankan PowerShell/VS Code sebagai Administrator.")
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

        key = (
            connection.pid, local_ip, local_port,
            remote_ip, remote_port, state
        )
        if key in seen:
            continue
        seen.add(key)

        pid = connection.pid
        process_name = get_process_name(pid)
        remote_type = classify_ip(remote_ip)
        risk, reason = get_connection_assessment(
            state, remote_type, pid, process_name
        )

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

        print(
            f"{process_name:<20} "
            f"PID: {str(result['pid']):<7} "
            f"{result['local_address']} -> {result['remote_address']} "
            f"| {state:<12} | {risk}"
        )

    if not results:
        print("Tidak ditemukan koneksi dengan alamat tujuan saat pemeriksaan.")

    return sorted(
        results,
        key=lambda item: (
            {"HIGH": 0, "REVIEW": 1, "INFO": 2, "LOW": 3}.get(item["risk"], 4),
            item["process"]
        )
    )


def check_firewall():
    """Memeriksa status Windows Firewall."""
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
    """Membaca konfigurasi SMB1 dan SMB2."""
    print("\n[5] PEMERIKSAAN SMB")
    command = (
        "Get-SmbServerConfiguration | "
        "Select-Object EnableSMB1Protocol, EnableSMB2Protocol | "
        "ConvertTo-Json -Compress"
    )
    output = run_powershell(command)

    try:
        data = json.loads(output)
        smb1 = data.get("EnableSMB1Protocol", "Unknown")
        smb2 = data.get("EnableSMB2Protocol", "Unknown")
        print(f"SMB1: {smb1}")
        print(f"SMB2: {smb2}")
        return {"smb1": str(smb1), "smb2": str(smb2), "raw": output}
    except Exception:
        print("Tidak dapat membaca konfigurasi SMB.")
        print(output)
        return {"smb1": "Unknown", "smb2": "Unknown", "raw": output}


def normalize_network_category(category):
    """Mengubah kategori jaringan Windows menjadi nama yang mudah dibaca."""
    mapping = {
        "0": "Public",
        "1": "Private",
        "2": "DomainAuthenticated",
        "PUBLIC": "Public",
        "PRIVATE": "Private",
        "DOMAINAUTHENTICATED": "DomainAuthenticated"
    }
    return mapping.get(str(category).upper(), str(category))


def check_network_profile():
    """Membaca kategori jaringan Windows."""
    print("\n[6] PEMERIKSAAN PROFIL JARINGAN")
    command = (
        "Get-NetConnectionProfile | "
        "Select-Object InterfaceAlias, NetworkCategory | "
        "ConvertTo-Json -Compress"
    )
    output = run_powershell(command)

    try:
        data = json.loads(output)
        if isinstance(data, dict):
            data = [data]

        profiles = []
        for item in data:
            alias = item.get("InterfaceAlias", "Unknown")
            raw_category = item.get("NetworkCategory", "Unknown")
            category = normalize_network_category(raw_category)
            profiles.append({
                "interface": alias,
                "category": category,
                "raw_category": str(raw_category)
            })
            print(f"Interface: {alias} | Profil: {category}")

        if not profiles:
            print("Tidak ada profil jaringan yang terbaca.")
        return profiles
    except Exception:
        print("Tidak dapat membaca profil jaringan.")
        print(output)
        return []


def check_file_signature(file_path):
    """Memeriksa tanda tangan digital file EXE."""
    path = Path(file_path)

    if not path.exists():
        return "FILE NOT FOUND"

    safe_path = str(path).replace("'", "''")
    command = (
        f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}').Status"
    )
    output = run_powershell(command)
    return output.strip() or "UNKNOWN"


def find_lms_processes():
    """Mencari LMS.exe yang sedang berjalan tanpa mengunci lokasi instalasi."""
    matches = []
    for process in psutil.process_iter(["pid", "name", "exe"]):
        try:
            if (process.info.get("name") or "").lower() == "lms.exe":
                matches.append({
                    "pid": process.info.get("pid"),
                    "path": process.info.get("exe") or ""
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess):
            continue
    return matches


def check_xampp_services(services):
    """Memeriksa keberadaan listener Apache dan MySQL XAMPP."""
    print("\n[7] PEMERIKSAAN APACHE DAN MYSQL")
    apache = [
        item for item in services
        if item["process"].lower() == "httpd.exe"
        or item["port"] in (80, 443, 8080, 8443)
    ]
    mysql = [
        item for item in services
        if item["process"].lower() in ("mysqld.exe", "mariadbd.exe")
        or item["port"] == 3306
    ]

    apache_status = "TERDETEKSI" if apache else "TIDAK TERDETEKSI"
    mysql_status = "TERDETEKSI" if mysql else "TIDAK TERDETEKSI"

    print(f"Apache/web listener : {apache_status}")
    print(f"MySQL listener      : {mysql_status}")

    for item in apache:
        print(
            f"  Web: {item['process']} | Port {item['port']} | "
            f"{item['addresses']} | {item['risk']}"
        )
    for item in mysql:
        print(
            f"  DB : {item['process']} | Port {item['port']} | "
            f"{item['addresses']} | {item['risk']}"
        )

    return {
        "apache_status": apache_status,
        "mysql_status": mysql_status,
        "apache_details": apache,
        "mysql_details": mysql
    }


def check_lms_signatures():
    """Memeriksa tanda tangan digital LMS.exe jika prosesnya ditemukan."""
    print("\n[8] PEMERIKSAAN TANDA TANGAN DIGITAL LMS")
    processes = find_lms_processes()

    if not processes:
        print("LMS.exe tidak sedang berjalan; pemeriksaan dilewati.")
        return [{"pid": "", "path": "", "signature": "PROCESS NOT RUNNING"}]

    results = []
    for item in processes:
        path = item["path"]
        if not path:
            status = "PATH UNAVAILABLE"
        else:
            status = check_file_signature(path)

        results.append({
            "pid": item["pid"],
            "path": path,
            "signature": status
        })
        print(f"PID: {item['pid']} | File: {path or 'Unknown'}")
        print(f"Signature: {status}")

    return results


def write_csv(path, rows, fields):
    """Menulis CSV dengan encoding yang kompatibel dengan Excel."""
    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def save_reports(port_results, services, active_connections,
                 firewall, firewall_raw, smb, profiles,
                 xampp, signatures, now):
    """Menyimpan laporan TXT dan empat jenis CSV."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = now.strftime("%Y%m%d_%H%M%S")

    txt_path = REPORT_DIR / f"security_report_{timestamp}.txt"
    ports_csv = REPORT_DIR / f"port_scan_{timestamp}.csv"
    services_csv = REPORT_DIR / f"listening_services_{timestamp}.csv"
    connections_csv = REPORT_DIR / f"active_connections_{timestamp}.csv"
    signatures_csv = REPORT_DIR / f"digital_signatures_{timestamp}.csv"

    lines = [
        "NETWORK SECURITY ANALYZER v2.3",
        "=" * 70,
        f"Waktu pemeriksaan: {now.isoformat(timespec='seconds')}",
        f"Target port scan: {TARGET}",
        "",
        "PORT SCAN LOCALHOST",
        "-" * 70
    ]

    for item in port_results:
        lines.append(f"Port {item['port']}: {item['status']}")

    lines += ["", "LISTENING SERVICES", "-" * 70]
    for item in services:
        lines.append(
            f"PID: {item['pid']} | Proses: {item['process']} | "
            f"Port: {item['port']} | IP: {item['addresses']} | "
            f"Risk: {item['risk']} | Keterangan: {item['reason']}"
        )

    lines += ["", "ACTIVE CONNECTIONS", "-" * 70]
    for item in active_connections:
        lines.append(
            f"PID: {item['pid']} | Proses: {item['process']} | "
            f"Lokal: {item['local_address']} | Tujuan: {item['remote_address']} | "
            f"Tipe tujuan: {item['remote_type']} | Status: {item['state']} | "
            f"Risk: {item['risk']} | Keterangan: {item['reason']}"
        )

    lines += [
        "", "WINDOWS FIREWALL", firewall,
        firewall_raw,
        "", "SMB CONFIGURATION",
        f"SMB1: {smb['smb1']}",
        f"SMB2: {smb['smb2']}",
        "", "NETWORK PROFILES"
    ]

    for profile in profiles:
        lines.append(f"{profile['interface']}: {profile['category']}")

    lines += [
        "", "XAMPP SERVICES",
        f"Apache: {xampp['apache_status']}",
        f"MySQL: {xampp['mysql_status']}",
        "", "DIGITAL SIGNATURES"
    ]

    for item in signatures:
        lines.append(
            f"PID: {item['pid']} | Path: {item['path']} | "
            f"Signature: {item['signature']}"
        )

    lines += [
        "", "CATATAN ANALISIS",
        "Label risiko adalah pemeriksaan awal, bukan bukti kompromi.",
        "Koneksi ke IP publik tidak otomatis berarti berbahaya.",
        "TIME_WAIT adalah status koneksi yang sedang/baru saja ditutup.",
        "Port listening belum tentu dapat diakses dari internet.",
        "Firewall memfilter lalu lintas; listener dapat tetap terlihat.",
        "Periksa identitas proses, tujuan koneksi, firewall, dan kebutuhan layanan."
    ]

    txt_path.write_text("\n".join(lines), encoding="utf-8")

    write_csv(ports_csv, port_results, ["host", "port", "status"])
    write_csv(
        services_csv, services,
        ["pid", "process", "port", "addresses", "risk", "reason"]
    )
    write_csv(
        connections_csv, active_connections,
        [
            "pid", "process", "local_address", "remote_address",
            "remote_type", "state", "risk", "reason"
        ]
    )
    write_csv(
        signatures_csv, signatures,
        ["pid", "path", "signature"]
    )

    print("\n[9] LAPORAN BERHASIL DISIMPAN")
    print("TXT                 :", txt_path)
    print("CSV port scan       :", ports_csv)
    print("CSV listening       :", services_csv)
    print("CSV koneksi aktif   :", connections_csv)
    print("CSV tanda tangan    :", signatures_csv)


def main():
    now = datetime.now()

    print("=" * 70)
    print("                 NETWORK SECURITY ANALYZER v2.3")
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

    save_reports(
        port_results,
        services,
        active_connections,
        firewall,
        firewall_raw,
        smb,
        profiles,
        xampp,
        signatures,
        now
    )

    high_listening = sum(1 for item in services if item["risk"] == "HIGH")
    review_listening = sum(1 for item in services if item["risk"] == "REVIEW")
    review_connections = sum(
        1 for item in active_connections if item["risk"] == "REVIEW"
    )
    time_wait_count = sum(
        1 for item in active_connections
        if str(item["state"]).upper() == "TIME_WAIT"
    )
    public_established = sum(
        1 for item in active_connections
        if item["remote_type"] == "PUBLIC"
        and str(item["state"]).upper() == "ESTABLISHED"
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
    main()
