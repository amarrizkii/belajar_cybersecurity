
import csv
import json
import socket
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime

import psutil


# ==================================================
# NETWORK SECURITY ANALYZER v2.1
# Khusus pemeriksaan komputer sendiri (localhost)
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

TARGET = "127.0.0.1"
PORTS_TO_SCAN = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 27017
]

TIMEOUT = 0.4
NOW = datetime.now()


def run_powershell(command):
    """Menjalankan perintah PowerShell untuk membaca konfigurasi."""
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return result.stderr.strip() or "Tidak dapat membaca konfigurasi."
    except Exception as error:
        return f"Gagal menjalankan PowerShell: {error}"


def scan_local_ports():
    """Memeriksa port pada localhost, bukan komputer lain."""
    print("\n[1] PEMERIKSAAN PORT LOCALHOST")
    results = []

    for port in PORTS_TO_SCAN:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        try:
            status = sock.connect_ex((TARGET, port))
            state = "OPEN" if status == 0 else "CLOSED"
        except Exception:
            state = "ERROR"
        finally:
            sock.close()

        results.append({
            "host": TARGET,
            "port": port,
            "status": state
        })

        print(f"Port {port:<6} : {state}")

    return results


def get_process_name(pid):
    """Mengambil nama proses berdasarkan PID."""
    if pid is None:
        return "Unknown"

    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"


def get_risk(port, addresses):
    """
    Penilaian awal berdasarkan jenis port dan alamat binding.
    Label bukan bukti bahwa suatu layanan telah diretas.
    """
    normalized = [str(address).split("%")[0] for address in addresses]

    loopback_only = bool(normalized) and all(
        is_loopback(address) for address in normalized
    )

    if loopback_only:
        return "LOW", "Hanya menerima koneksi dari komputer sendiri"

    high_ports = {
        3306: "MySQL perlu dibatasi jika tidak digunakan dari jaringan",
        445: "SMB perlu diperiksa akses jaringan dan aturan firewall",
        3389: "RDP perlu dipastikan hanya dapat diakses pihak berwenang",
        5900: "VNC perlu diperiksa autentikasi dan akses jaringannya",
        6379: "Redis perlu diperiksa autentikasi dan akses jaringannya",
        27017: "MongoDB perlu diperiksa autentikasi dan akses jaringannya"
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
        return "INFO", "Layanan web; pastikan hanya layanan yang diperlukan aktif"

    if port == 135 or 49664 <= port <= 49685:
        return "INFO", "Layanan RPC Windows; bukan otomatis kerentanan"

    if port in (623, 16992):
        return "REVIEW", "Periksa layanan manajemen perangkat Intel"

    return "REVIEW", "Periksa identitas layanan dan kebutuhan akses jaringan"


def is_loopback(address):
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def get_listening_services():
    """
    Mengambil socket LISTEN dan menggabungkan IPv4/IPv6
    berdasarkan PID dan port.
    """
    print("\n[2] PEMERIKSAAN LAYANAN LISTENING")

    grouped = {}

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Akses ditolak. Coba jalankan VS Code sebagai Administrator.")
        return []

    for connection in connections:
        if connection.status != psutil.CONN_LISTEN:
            continue

        if not connection.laddr:
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

    return sorted(results, key=lambda x: x["port"])


def check_firewall():
    """Memeriksa status Windows Firewall."""
    print("\n[3] PEMERIKSAAN WINDOWS FIREWALL")

    output = run_powershell(
        "netsh advfirewall show allprofiles state"
    )

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
    print("\n[4] PEMERIKSAAN SMB")

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

        return {
            "smb1": str(smb1),
            "smb2": str(smb2),
            "raw": output
        }
    except Exception:
        print("Tidak dapat membaca konfigurasi SMB.")
        print(output)

        return {
            "smb1": "Unknown",
            "smb2": "Unknown",
            "raw": output
        }


def check_network_profile():
    """Membaca kategori jaringan Windows."""
    print("\n[5] PEMERIKSAAN PROFIL JARINGAN")

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
            category = item.get("NetworkCategory", "Unknown")

            profiles.append({
                "interface": alias,
                "category": category
            })

            print(f"Interface: {alias} | Profil: {category}")

        return profiles

    except Exception:
        print("Tidak dapat membaca profil jaringan.")
        print(output)
        return []


def check_file_signature(file_path):
    """Memeriksa tanda tangan digital file EXE."""
    print("\n[6] PEMERIKSAAN TANDA TANGAN DIGITAL")

    path = Path(file_path)

    if not path.exists():
        print("File tidak ditemukan:", path)
        return "FILE NOT FOUND"

    safe_path = str(path).replace("'", "''")

    command = (
        f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}').Status"
    )

    output = run_powershell(command)
    status = output.strip() or "UNKNOWN"

    print(f"File: {path.name}")
    print(f"Signature: {status}")

    return status


def save_reports(port_results, services, firewall, smb,
                 profiles, signature):
    """Menyimpan laporan TXT dan CSV."""
    REPORT_DIR.mkdir(exist_ok=True)

    timestamp = NOW.strftime("%Y%m%d_%H%M%S")
    txt_path = REPORT_DIR / f"security_report_{timestamp}.txt"
    csv_path = REPORT_DIR / f"security_report_{timestamp}.csv"

    lines = [
        "NETWORK SECURITY ANALYZER v2.1",
        "=" * 55,
        f"Waktu pemeriksaan: {NOW}",
        f"Target port scan: {TARGET}",
        "",
        "PORT SCAN LOCALHOST",
        "-" * 55
    ]

    for item in port_results:
        lines.append(
            f"Port {item['port']}: {item['status']}"
        )

    lines += [
        "",
        "LISTENING SERVICES",
        "-" * 55
    ]

    for item in services:
        lines.append(
            f"PID: {item['pid']} | "
            f"Proses: {item['process']} | "
            f"Port: {item['port']} | "
            f"IP: {item['addresses']} | "
            f"Risk: {item['risk']} | "
            f"Keterangan: {item['reason']}"
        )

    lines += [
        "",
        "WINDOWS FIREWALL",
        firewall,
        "",
        "SMB CONFIGURATION",
        f"SMB1: {smb['smb1']}",
        f"SMB2: {smb['smb2']}",
        "",
        "NETWORK PROFILES"
    ]

    for profile in profiles:
        lines.append(
            f"{profile['interface']}: {profile['category']}"
        )

    lines += [
        "",
        "DIGITAL SIGNATURE",
        signature,
        "",
        "CATATAN:",
        "Label risiko adalah pemeriksaan awal, bukan bukti kompromi.",
        "Port yang listening belum tentu dapat diakses dari internet.",
        "Periksa firewall, kebutuhan layanan, dan autentikasi.",
    ]

    txt_path.write_text("\n".join(lines), encoding="utf-8")

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:
        fields = [
            "pid", "process", "port",
            "addresses", "risk", "reason"
        ]

        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(services)

    print("\n[7] LAPORAN BERHASIL DISIMPAN")
    print("TXT :", txt_path)
    print("CSV :", csv_path)


def main():
    print("=" * 55)
    print("       NETWORK SECURITY ANALYZER v2.1")
    print("=" * 55)

    port_results = scan_local_ports()
    services = get_listening_services()
    firewall, _ = check_firewall()
    smb = check_smb()
    profiles = check_network_profile()

    lms_path = (
        r"C:\WINDOWS\System32\DriverStore\FileRepository"
        r"\lms.inf_amd64_dd349ca1e8d98184\LMS.exe"
    )

    signature = check_file_signature(lms_path)

    save_reports(
        port_results,
        services,
        firewall,
        smb,
        profiles,
        signature
    )

    print("\n" + "=" * 55)
    print("ANALISIS SELESAI")
    print("Jumlah port diperiksa :", len(port_results))
    print("Jumlah layanan unik   :", len(services))
    print("Jumlah HIGH           :", sum(
        1 for item in services if item["risk"] == "HIGH"
    ))
    print("Jumlah REVIEW         :", sum(
        1 for item in services if item["risk"] == "REVIEW"
    ))
    print("=" * 55)


if __name__ == "__main__":
    main()
