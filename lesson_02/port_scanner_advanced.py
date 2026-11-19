
# ==========================================
# CYBER SECURITY LAB
# ADVANCED LOCALHOST PORT SCANNER
# ==========================================

import socket
from datetime import datetime

target = "127.0.0.1"

ports = {
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
    8443: "HTTPS Alternative"
}

hasil = []

waktu_mulai = datetime.now()

print("=" * 50)
print("       ADVANCED CYBER SECURITY SCANNER")
print("=" * 50)

print("Target       :", target)
print("Waktu mulai  :", waktu_mulai.strftime("%d-%m-%Y %H:%M:%S"))
print("-" * 50)

for port, layanan in ports.items():

    scanner = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    scanner.settimeout(1)

    status = scanner.connect_ex((target, port))

    if status == 0:
        pesan = f"[TERBUKA] Port {port} - {layanan}"
        hasil.append(pesan)
        print(pesan)
    else:
        print(f"[TUTUP]   Port {port} - {layanan}")

    scanner.close()

waktu_selesai = datetime.now()

print("-" * 50)
print("Pemindaian selesai!")
print("Durasi:", waktu_selesai - waktu_mulai)

# Simpan laporan
with open("hasil_scan.txt", "w", encoding="utf-8") as file:

    file.write("LAPORAN CYBER SECURITY SCAN\n")
    file.write(f"Target: {target}\n")
    file.write(f"Waktu: {waktu_mulai}\n\n")

    file.write("PORT TERBUKA:\n")

    for item in hasil:
        file.write(item + "\n")

    file.write(f"\nTotal port terbuka: {len(hasil)}")

print("\nLaporan disimpan ke hasil_scan.txt")
