
# ==========================================
# CYBER SECURITY LAB
# LESSON 02 - PASSWORD SECURITY CHECKER
# ==========================================

print("====================================")
print("      PASSWORD SECURITY CHECKER")
print("====================================")

password = input("amar 1 2 3: ")

score = 0

# Pemeriksaan panjang password
if len(password) >= 8:
    score += 1

if len(password) >= 12:
    score += 1

# Pemeriksaan huruf besar
if any(char.isupper() for char in password):
    score += 1

# Pemeriksaan huruf kecil
if any(char.islower() for char in password):
    score += 1

# Pemeriksaan angka
if any(char.isdigit() for char in password):
    score += 1

# Pemeriksaan simbol
if any(not char.isalnum() for char in password):
    score += 1

# Hasil pemeriksaan
print("\n========== HASIL ANALISIS ==========")

print("Panjang password:", len(password))
print("Skor keamanan:", score, "/ 6")

if score <= 2:
    print("Status: LEMAH")
    print("Saran: Gunakan password lebih panjang dan bervariasi.")

elif score <= 4:
    print("Status: SEDANG")
    print("Saran: Tambahkan kombinasi angka dan simbol.")

else:
    print("Status: KUAT")
    print("Saran: Pertahankan password yang panjang dan unik.")

print("====================================")
