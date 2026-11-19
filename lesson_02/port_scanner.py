
# ==========================================
# CYBER SECURITY LAB
# LESSON 03 - LOCALHOST PORT SCANNER
# ==========================================

import socket

target = "127.0.0.1"

ports = [80, 443, 3306, 8080, 21, 22]

print("================================")
print("       PYTHON PORT SCANNER")
print("================================")

print("Target:", target)
print("Memulai pemindaian...\n")

for port in ports:

    scanner = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    scanner.settimeout(1)

    result = scanner.connect_ex((target, port))

    if result == 0:
        print(f"[TERBUKA] Port {port}")
    else:
        print(f"[TUTUP]   Port {port}")

    scanner.close()

print("\nPemindaian selesai.")
