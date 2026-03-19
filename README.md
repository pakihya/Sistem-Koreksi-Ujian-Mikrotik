# Penilai MT — Sistem Koreksi Konfigurasi MikroTik

Aplikasi penilaian ujian praktik konfigurasi router MikroTik berbasis GUI. Dirancang untuk lingkungan lab sekolah (SMK/sederajat) agar guru dapat menilai konfigurasi router siswa secara otomatis — tanpa perlu memeriksa satu per satu, dan **tanpa perlu menginstal apapun di komputer siswa**.

---

## Fitur Utama

- Guru koreksi langsung ke router siswa via MikroTik API (port 8728)
- Siswa **tidak perlu menjalankan program apapun** — cukup router MikroTik aktif
- Nama siswa diambil otomatis dari `system identity` router
- Parameter soal bisa berbeda tiap siswa (misal: identity name, IP address)
- Koreksi semua router secara paralel sekaligus
- Token SHA-256 anti-manipulasi pada setiap hasil
- Export rekap nilai ke CSV
- Kompatibel dengan semua versi RouterOS (< 6.43, 6.43–6.x, 7.x)

---

## Struktur Aplikasi

```
penilai-mt/
├── penilai_mt.py               # Aplikasi utama (dijalankan guru)
├── soal/
│   ├── basicmikrotik.json      # Contoh soal: konfigurasi dasar
│   └── lanjutanmikrotik.json   # Contoh soal: konfigurasi lanjutan
├── contoh_hasil/
│   └── hasil_basicmikrotik_contoh.json
└── README.md
```

---

## Persyaratan Sistem

**Komputer Guru (Windows/Linux):**
- Python 3.8 atau lebih baru
- Tkinter (sudah termasuk di instalasi Python Windows)
- Tidak perlu `pip install` apapun — hanya library standar Python
- Terhubung ke jaringan lokal yang sama dengan router siswa

**Router MikroTik Siswa:**
- MikroTik API service aktif di port 8728
- Dapat diakses dari jaringan guru

---

## Instalasi

### 1. Unduh file aplikasi

Klik tombol **"Code" → "Download ZIP"** di halaman repositori ini,
lalu ekstrak ke folder pilihan Anda, misalnya:

```
C:\penilai-mt\
```

### 2. Pastikan Python sudah terinstal

Buka Command Prompt, ketik:

```
python --version
```

Jika belum ada, unduh Python dari **https://python.org/downloads** —
pilih versi terbaru, centang **"Add Python to PATH"** saat instalasi.

### 3. Aktifkan MikroTik API di router siswa

Masuk ke router via Winbox atau terminal MikroTik, jalankan:

```
/ip service enable api
```

Port default **8728** sudah cukup. Tidak perlu konfigurasi tambahan.

### 4. Jalankan aplikasi

```
python penilai_mt.py
```

---

## Cara Penggunaan

### Di Komputer Guru

**1. Muat file soal**

Klik tombol **"Muat Soal JSON…"** dan pilih file soal yang sesuai ujian
(misal `basicmikrotik.json`).

**2. Tambah router siswa**

Klik **"+ Tambah"**, isi data koneksi router:

```
IP Router  : 192.168.88.1   ← IP MikroTik siswa
Port API   : 8728            ← biarkan default
Username   : admin
Password   :                 ← kosongkan jika tidak ada password
```

Di bagian bawah dialog, parameter soal yang bisa di-override per siswa
akan tampil otomatis. Contoh: ubah `nama` pada soal `identity` sesuai
nama yang diminta soal untuk siswa tersebut.

**3. Koreksi**

- Klik **"▶ Koreksi Dipilih"** untuk koreksi satu siswa yang sedang dipilih
- Klik **"▶▶ Koreksi Semua"** untuk koreksi seluruh daftar sekaligus (paralel)

Nama siswa akan terisi otomatis dari `system identity` router setelah koreksi.

**4. Lihat detail**

Klik nama siswa di daftar kiri untuk melihat detail per soal di panel kanan:
nilai, bobot, status lulus/gagal, dan keterangan teknis dari router.

**5. Export nilai**

Klik **"Export CSV"** untuk menyimpan rekap nilai seluruh siswa.

---

## Format File Soal (JSON)

Buat file `<nama-ujian>.json` dengan struktur berikut:

```json
{
  "ujian": {
    "nama": "Nama Ujian Lengkap",
    "kode": "kode-ujian",
    "versi": "1.0"
  },
  "soal": [
    {
      "nomor": 1,
      "tipe": "<tipe_checker>",
      "deskripsi": "Deskripsi soal yang ditampilkan",
      "bobot": 25,
      "...": "parameter tergantung tipe"
    }
  ]
}
```

Nilai akhir dihitung proporsional: `(total poin / total bobot) × 100`

---

## Tipe Checker yang Tersedia

| Tipe | Memeriksa | Parameter |
|------|-----------|-----------|
| `identity` | Nama router (System Identity) | `nama` |
| `dhcp_client` | DHCP client aktif pada interface | `interface`, `disabled` |
| `ip_address` | IP address pada interface | `address`, `interface` |
| `nat_masquerade` | NAT srcnat masquerade | `out_interface` |
| `static_route` | Static route / default gateway | `dst_address`, `gateway` |
| `dns` | DNS server setting | `servers`, `allow_remote_requests` |
| `bridge` | Bridge dan member interface | `name`, `members` |
| `service` | IP service aktif/nonaktif | `name`, `disabled` |
| `user` | Local user MikroTik | `name`, `group` |
| `wireless` | Konfigurasi wireless | `interface`, `ssid`, `security_profile` |

### Contoh konfigurasi soal

```json
{ "nomor": 1, "tipe": "identity",
  "deskripsi": "System identity sesuai nama siswa",
  "bobot": 20, "nama": "NAMA-SISWA" }

{ "nomor": 2, "tipe": "dhcp_client",
  "deskripsi": "DHCP client aktif pada ether1",
  "bobot": 20, "interface": "ether1", "disabled": "false" }

{ "nomor": 3, "tipe": "ip_address",
  "deskripsi": "IP address LAN pada ether2",
  "bobot": 30, "address": "192.168.10.1/24", "interface": "ether2" }

{ "nomor": 4, "tipe": "nat_masquerade",
  "deskripsi": "NAT masquerade srcnat via ether1",
  "bobot": 30, "out_interface": "ether1" }

{ "nomor": 5, "tipe": "static_route",
  "deskripsi": "Default route ke gateway ISP",
  "bobot": 10, "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1" }

{ "nomor": 6, "tipe": "dns",
  "deskripsi": "DNS 8.8.8.8 dengan allow-remote-requests",
  "bobot": 10, "servers": "8.8.8.8", "allow_remote_requests": "yes" }

{ "nomor": 7, "tipe": "bridge",
  "deskripsi": "Bridge LAN dengan member ether2 dan ether3",
  "bobot": 10, "name": "bridge-lan", "members": ["ether2", "ether3"] }

{ "nomor": 8, "tipe": "service",
  "deskripsi": "SSH diaktifkan",
  "bobot": 5, "name": "ssh", "disabled": "false" }

{ "nomor": 9, "tipe": "user",
  "deskripsi": "User operator dengan group read",
  "bobot": 5, "name": "operator", "group": "read" }
```

> Untuk `ip_address`, isi `"address": "any"` jika hanya ingin cek
> keberadaan IP pada interface tanpa memeriksa nilai IP-nya.

---

## Menambah Tipe Checker Baru

Buka `penilai_mt.py`, tambahkan fungsi checker dan daftarkan di `CHECKER_MAP`:

```python
def cek_tipe_baru(api, params):
    # api    : objek MikroTikAPI yang sudah terkoneksi dan login
    # params : dict parameter dari soal JSON
    # return : (bool lulus, str keterangan)
    hasil = api.query("/perintah/mikrotik/print")
    return True, "keterangan hasil"

CHECKER_MAP = {
    # ... checker yang sudah ada ...
    "tipe_baru": cek_tipe_baru,
}
```

Lalu gunakan `"tipe": "tipe_baru"` di file JSON soal. Tidak perlu ubah kode lain.

---

## Format File Hasil

Hasil koreksi yang ditampilkan di GUI dan dapat di-export ke CSV:

```json
{
  "ujian": { "nama": "Ujian Praktik Dasar MikroTik", "kode": "basicmikrotik" },
  "identity": "Budi-RT01",
  "host": "192.168.88.1",
  "nilai": 90.0,
  "total_soal": 4,
  "total_benar": 3,
  "total_bobot": 100,
  "token": "A3F9C12B4E78",
  "waktu": "2025-07-01T09:15:42",
  "status": "ok",
  "detail": [
    {
      "nomor": 1,
      "tipe": "identity",
      "deskripsi": "System identity sesuai nama siswa",
      "bobot": 20,
      "nilai": 20,
      "lulus": true,
      "keterangan": "identity='Budi-RT01'"
    }
  ]
}
```

---

## Kompatibilitas RouterOS

| Versi ROS | Protokol Login |
|-----------|---------------|
| < 6.43 | MD5 challenge-response (fallback otomatis) |
| 6.43 – 6.x | Plain-text (prioritas) |
| 7.x | Plain-text langsung |

Aplikasi mendeteksi dan menyesuaikan protokol login secara otomatis.

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `Gagal koneksi` | Cek IP router. Jalankan `/ip service enable api` di MikroTik |
| `Login gagal` | Cek username/password. Kosongkan field password jika tidak ada |
| `Soal selalu salah` | Cek nama field di soal JSON — `disabled` gunakan nilai `"false"`/`"true"` |
| `tkinter not found` | Windows: reinstall Python, centang tcl/tk. Linux: `sudo apt install python3-tk` |

---

## Lisensi

MIT License — bebas digunakan dan dimodifikasi untuk keperluan pendidikan.
