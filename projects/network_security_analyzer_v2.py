
import socket
import psutil
import subprocess
import csv
import os
from datetime import datetime

# =====================================================
# PYTHON NETWORK SECURITY ANALYZER V2.0
# Windows | Local Security Analysis
# =====================================================

VERSION = "2.0"
REPORT_TXT = "hasil_analisis_v2.txt"
REPORT_CSV = "hasil_analisis_v2.csv"

TARGET = "127.0.0.1"

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternative",
    8443: "HTTPS Alternative",
    27017: "MongoDB"
}

SENSITIVE_PORTS = {
    21, 23, 139, 445, 3389, 5900,
    3306, 5432, 6379, 27017
}


def garis():
    print("=" * 70)


def judul():
    os.system("cls" if os.name == "nt" else "clear")
    garis()
    print("          PYTHON NETWORK SECURITY ANALYZER")
    print("                       VERSION", VERSION)
    garis()
    print("Target:", TARGET)
    print("Waktu :", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))
    garis()


def scan_ports():
    print("\n[1] TCP PORT SCANNER")
    hasil = []

    for port, service in PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        try:
            status = sock.connect_ex((TARGET, port))
            kondisi = "OPEN" if status == 0 else "CLOSED"
        except OSError:
            kondisi = "ERROR"
        finally:
            sock.close()

        print(f"[{kondisi:<6}] Port {port:<5} {service}")

        hasil.append({
            "type": "PORT SCAN",
            "ip": TARGET,
            "port": port,
            "status": kondisi,
            "pid": "",
            "process": "",
            "risk": "INFORMATIONAL",
            "recommendation": "Periksa kebutuhan layanan."
        })

    return hasil


def get_process_name(pid):
    if not pid:
        return "Tidak diketahui"

    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Tidak dapat diakses"


def get_risk(ip, port):
    # Loopback hanya menerima koneksi lokal.
    if ip in ("127.0.0.1", "::1"):
        return (
            "LOW",
            "Koneksi lokal. Pastikan layanan memang diperlukan."
        )

    # Port sensitif yang mendengarkan pada semua interface.
    if port in SENSITIVE_PORTS:
        return (
            "HIGH",
            "Batasi akses melalui firewall dan hindari paparan "
            "layanan sensitif ke jaringan yang tidak dipercaya."
        )

    # Layanan yang mendengarkan pada semua interface.
    if ip in ("0.0.0.0", "::"):
        return (
            "MEDIUM",
            "Periksa kebutuhan akses jaringan dan batasi "
            "akses menggunakan Windows Firewall."
        )

    # IP jaringan lokal selain loopback.
    return (
        "MEDIUM",
        "Periksa perangkat yang dapat mengakses layanan ini."
    )


def analyze_connections():
    print("\n[2] LISTENING CONNECTION ANALYZER")

    hasil = []

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("Akses ditolak. Coba jalankan VS Code sebagai Administrator.")
        return hasil

    for conn in connections:
        if conn.status != psutil.CONN_LISTEN:
            continue

        if not conn.laddr:
            continue

        ip = conn.laddr.ip
        port = conn.laddr.port
        pid = conn.pid
        process = get_process_name(pid)
        risk, recommendation = get_risk(ip, port)

        service = PORTS.get(port, "Unknown")

        data = {
            "type": "LISTENING",
            "ip": ip,
            "port": port,
            "status": "LISTENING",
            "pid": pid if pid is not None else "",
            "process": process,
            "risk": risk,
            "recommendation": recommendation
        }

        hasil.append(data)

        print(
            f"[{risk:<13}] {ip:<18} "
            f"PORT {port:<6} "
            f"PID {str(pid):<8} "
            f"{process} ({service})"
        )

    print("\nTotal listening:", len(hasil))
    return hasil


def check_firewall():
    print("\n[3] WINDOWS FIREWALL CHECKER")

    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall",
                "show", "allprofiles", "state"
            ],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout
        print(output if output else result.stderr)

        states = []

        for line in output.splitlines():
            line = line.strip().upper()

            if line.startswith("STATE"):
                if "ON" in line:
                    states.append("ON")
                elif "OFF" in line:
                    states.append("OFF")

        if states and all(state == "ON" for state in states):
            status = "ON"
            print("Kesimpulan: Semua profil yang terdeteksi aktif.")
        elif states and any(state == "OFF" for state in states):
            status = "OFF / PARTIAL"
            print("PERINGATAN: Ada profil firewall yang tidak aktif.")
        else:
            status = "UNKNOWN"
            print("Status firewall belum dapat dipastikan.")

        return status

    except (subprocess.SubprocessError, OSError) as error:
        print("Gagal memeriksa firewall:", error)
        return "ERROR"


def check_signature():
    print("\n[4] DIGITAL SIGNATURE CHECKER")

    path = input(
        "Masukkan lokasi file EXE (Enter untuk melewati): "
    ).strip().strip('"')

    if not path:
        print("Pemeriksaan dilewati.")
        return "SKIPPED"

    if not os.path.isfile(path):
        print("File tidak ditemukan.")
        return "NOT FOUND"

    command = (
        "Get-AuthenticodeSignature -LiteralPath "
        "'{}' | Select-Object -ExpandProperty Status"
    ).format(path.replace("'", "''"))

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                command
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        status = result.stdout.strip()

        if not status:
            status = "UNKNOWN"

        print("Status tanda tangan:", status)
        return status

    except (subprocess.SubprocessError, OSError) as error:
        print("Gagal memeriksa:", error)
        return "ERROR"


def analyze_summary(ports, connections, firewall):
    print("\n[5] SECURITY RISK SUMMARY")

    open_ports = [
        item for item in ports
        if item["status"] == "OPEN"
    ]

    high = [
        item for item in connections
        if item["risk"] == "HIGH"
    ]

    medium = [
        item for item in connections
        if item["risk"] == "MEDIUM"
    ]

    low = [
        item for item in connections
        if item["risk"] == "LOW"
    ]

    print("Port terbuka localhost :", len(open_ports))
    print("Risiko HIGH            :", len(high))
    print("Risiko MEDIUM          :", len(medium))
    print("Risiko LOW             :", len(low))
    print("Windows Firewall       :", firewall)

    print("\nREKOMENDASI:")

    if high:
        print("- Periksa layanan dengan kategori HIGH.")
        print("- Pastikan port sensitif tidak terbuka ke jaringan umum.")

    if medium:
        print("- Periksa layanan yang mendengarkan pada semua interface.")

    if firewall != "ON":
        print("- Periksa dan aktifkan Windows Firewall jika diperlukan.")

    if not high and not medium and firewall == "ON":
        print("- Tidak ditemukan indikator risiko tinggi dari pemeriksaan ini.")

    return {
        "open_ports": len(open_ports),
        "high": len(high),
        "medium": len(medium),
        "low": len(low)
    }


def save_reports(ports, connections, firewall, signature, summary):
    print("\n[6] REPORT GENERATOR")

    waktu = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    with open(REPORT_TXT, "w", encoding="utf-8") as file:
        file.write("PYTHON NETWORK SECURITY ANALYZER V2.0\n")
        file.write("=" * 60 + "\n")
        file.write(f"Waktu pemeriksaan: {waktu}\n")
        file.write(f"Target: {TARGET}\n")
        file.write(f"Windows Firewall: {firewall}\n")
        file.write(f"Digital Signature: {signature}\n\n")

        file.write("[PORT SCAN]\n")

        for item in ports:
            file.write(
                f"Port {item['port']} | {item['status']} | "
                f"{PORTS[item['port']]}\n"
            )

        file.write("\n[LISTENING CONNECTIONS]\n")

        for item in connections:
            file.write(
                f"{item['ip']}:{item['port']} | "
                f"PID: {item['pid']} | "
                f"Process: {item['process']} | "
                f"Risk: {item['risk']}\n"
                f"Recommendation: {item['recommendation']}\n\n"
            )

        file.write("\n[SECURITY SUMMARY]\n")

        for key, value in summary.items():
            file.write(f"{key}: {value}\n")

        file.write(
            "\nCATATAN:\n"
            "Kategori risiko merupakan penilaian awal berdasarkan "
            "alamat binding dan nomor port.\n"
            "Port terbuka tidak otomatis berarti rentan.\n"
            "Pemeriksaan ini bukan pengganti audit keamanan menyeluruh.\n"
        )

    semua_data = []

    for item in ports + connections:
        row = item.copy()
        row["firewall"] = firewall
        row["signature"] = signature
        semua_data.append(row)

    with open(
        REPORT_CSV,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:
        fieldnames = [
            "type", "ip", "port", "status",
            "pid", "process", "risk",
            "recommendation", "firewall", "signature"
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(semua_data)

    print("TXT berhasil dibuat:", REPORT_TXT)
    print("CSV berhasil dibuat:", REPORT_CSV)


def main():
    judul()

    ports = scan_ports()
    connections = analyze_connections()
    firewall = check_firewall()
    signature = check_signature()

    summary = analyze_summary(
        ports,
        connections,
        firewall
    )

    save_reports(
        ports,
        connections,
        firewall,
        signature,
        summary
    )

    garis()
    print("ANALISIS SELESAI")
    print("File laporan:")
    print("-", REPORT_TXT)
    print("-", REPORT_CSV)
    garis()


if __name__ == "__main__":
    main()
