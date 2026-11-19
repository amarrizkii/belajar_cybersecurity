
import socket
import psutil
import subprocess
import os
from datetime import datetime

# ==========================================
# NETWORK SECURITY ANALYZER
# Versi 1.0
# ==========================================

REPORT_FILE = "hasil_analisis_keamanan.txt"

PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP Alternative",
    8443: "HTTPS Alternative",
}


def garis():
    print("=" * 65)


def scan_ports():
    print("\n[1] PEMERIKSAAN PORT LOKAL")

    target = "127.0.0.1"
    ports = [21, 22, 25, 53, 80, 110, 143,
             443, 3306, 5432, 8080, 8443]

    hasil = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        status = sock.connect_ex((target, port))
        nama = PORT_NAMES.get(port, "Unknown")

        if status == 0:
            kondisi = "OPEN"
            print(f"[OPEN]   Port {port:<5} {nama}")
        else:
            kondisi = "CLOSED"
            print(f"[CLOSED] Port {port:<5} {nama}")

        hasil.append((port, nama, kondisi))
        sock.close()

    return hasil


def daftar_proses():
    print("\n[2] DAFTAR PROSES YANG BERJALAN")

    hasil = []

    for proses in psutil.process_iter(
        ["pid", "name"]
    ):
        try:
            info = proses.info
            nama = info["name"] or "Unknown"

            hasil.append(
                (info["pid"], nama)
            )

        except (psutil.NoSuchProcess,
                psutil.AccessDenied):
            continue

    hasil.sort(key=lambda x: x[0])

    for pid, nama in hasil[:30]:
        print(f"PID: {pid:<8} PROSES: {nama}")

    print(f"\nTotal proses terdeteksi: {len(hasil)}")

    return hasil


def analisis_koneksi():
    print("\n[3] ANALISIS KONEKSI LISTENING")

    hasil = []

    for koneksi in psutil.net_connections(kind="inet"):
        if koneksi.status == psutil.CONN_LISTEN:
            alamat = koneksi.laddr
            pid = koneksi.pid

            try:
                nama = psutil.Process(pid).name() if pid else "Tidak diketahui"
            except (psutil.NoSuchProcess,
                    psutil.AccessDenied):
                nama = "Tidak dapat diakses"

            data = {
                "ip": alamat.ip,
                "port": alamat.port,
                "pid": pid,
                "nama": nama
            }

            hasil.append(data)

            print(
                f"IP: {alamat.ip:<18} "
                f"PORT: {alamat.port:<6} "
                f"PID: {str(pid):<8} "
                f"PROSES: {nama}"
            )

    print(f"\nTotal koneksi listening: {len(hasil)}")

    return hasil


def periksa_tanda_tangan():
    print("\n[4] PEMERIKSAAN TANDA TANGAN DIGITAL")

    path = input(
        "Masukkan path file EXE (kosong untuk melewati): "
    ).strip().strip('"')

    if not path:
        print("Pemeriksaan tanda tangan dilewati.")
        return "Dilewati"

    if not os.path.isfile(path):
        print("File tidak ditemukan.")
        return "File tidak ditemukan"

    perintah = (
        "Get-AuthenticodeSignature -LiteralPath "
        "'{}' | Select-Object -ExpandProperty Status"
    ).format(path.replace("'", "''"))

    try:
        hasil = subprocess.run(
            ["powershell", "-NoProfile",
             "-Command", perintah],
            capture_output=True,
            text=True,
            timeout=15
        )

        status = hasil.stdout.strip() or "Tidak diketahui"

        print("Status tanda tangan:", status)

        return status

    except (subprocess.SubprocessError, OSError) as error:
        print("Gagal memeriksa:", error)
        return "Gagal diperiksa"


def simpan_laporan(ports, proses, koneksi, signature):
    print("\n[5] MENYIMPAN LAPORAN")

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write("NETWORK SECURITY ANALYZER\n")
        file.write("=" * 55 + "\n")
        file.write(
            "Waktu pemeriksaan: "
            + datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            + "\n\n"
        )

        file.write("[HASIL PEMERIKSAAN PORT]\n")

        for port, nama, kondisi in ports:
            file.write(
                f"Port {port} | {nama} | {kondisi}\n"
            )

        file.write("\n[DAFTAR PROSES]\n")

        for pid, nama in proses:
            file.write(f"PID {pid} | {nama}\n")

        file.write("\n[KONEKSI LISTENING]\n")

        for data in koneksi:
            file.write(
                f"{data['ip']}:{data['port']} | "
                f"PID: {data['pid']} | "
                f"Proses: {data['nama']}\n"
            )

        file.write(
            "\n[TANDA TANGAN DIGITAL]\n"
            + str(signature)
            + "\n"
        )

        file.write(
            "\nCATATAN:\n"
            "Port OPEN tidak otomatis berarti rentan.\n"
            "Hasil ini merupakan pemeriksaan dasar pada komputer lokal.\n"
        )

    print("Laporan berhasil disimpan:", REPORT_FILE)


def main():
    os.system("cls" if os.name == "nt" else "clear")

    garis()
    print("       PYTHON NETWORK SECURITY ANALYZER")
    print("                    VERSION 1.0")
    garis()

    print("Target pemeriksaan: Komputer sendiri (127.0.0.1)")

    ports = scan_ports()
    proses = daftar_proses()
    koneksi = analisis_koneksi()
    signature = periksa_tanda_tangan()

    simpan_laporan(
        ports,
        proses,
        koneksi,
        signature
    )

    garis()
    print("PEMERIKSAAN SELESAI")
    print("Buka file:", REPORT_FILE)
    garis()


if __name__ == "__main__":
    main()
