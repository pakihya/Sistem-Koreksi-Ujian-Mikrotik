"""
penilai_mt.py — Alat koreksi MikroTik untuk guru (pure client-side)
Guru langsung koreksi router siswa via MikroTik API (port 8728).
Siswa tidak perlu jalankan apa pun.

Cara pakai:
    python penilai_mt.py

Tidak perlu install library apapun (pure stdlib + tkinter).
Python 3.8+ di Windows/Linux.
"""

import csv
import hashlib
import json
import os
import socket
import struct
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

# ══════════════════════════════════════════════
# MIKROTIK API CLIENT (pure stdlib)
# ══════════════════════════════════════════════

class MikroTikAPIError(Exception):
    pass


class MikroTikAPI:
    def __init__(self, host, port=8728, timeout=8):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            try: self.sock.close()
            except Exception: pass
            self.sock = None

    @staticmethod
    def _enc(n):
        if n < 0x80:         return bytes([n])
        elif n < 0x4000:     return struct.pack("!H", n | 0x8000)
        elif n < 0x200000:   return struct.pack("!I", n | 0xC00000)[1:]
        elif n < 0x10000000: return struct.pack("!I", n | 0xE0000000)
        else:                return b'\xF0' + struct.pack("!I", n)

    @staticmethod
    def _dec(sock):
        f = sock.recv(1)
        if not f: raise MikroTikAPIError("Koneksi terputus")
        f = f[0]
        if f < 0x80:   return f
        elif f < 0xC0: return ((f & ~0x80) << 8) | sock.recv(1)[0]
        elif f < 0xE0:
            r = sock.recv(2); return ((f & ~0xC0) << 16) | (r[0] << 8) | r[1]
        elif f < 0xF0:
            r = sock.recv(3); return ((f & ~0xE0) << 24) | (r[0] << 16) | (r[1] << 8) | r[2]
        else: return struct.unpack("!I", sock.recv(4))[0]

    def _write(self, words):
        data = b""
        for w in words:
            e = w.encode(); data += self._enc(len(e)) + e
        self.sock.sendall(data + b'\x00')

    def _read_sentence(self):
        words = []
        while True:
            n = self._dec(self.sock)
            if n == 0: break
            buf = b""
            while len(buf) < n:
                c = self.sock.recv(n - len(buf))
                if not c: raise MikroTikAPIError("Terputus saat baca")
                buf += c
            words.append(buf.decode("utf-8", errors="replace"))
        return words

    def _read_response(self):
        rows = []
        while True:
            s = self._read_sentence()
            if not s: continue
            tag = s[0]
            rec = {}
            for w in s[1:]:
                if w.startswith("="):
                    p = w[1:].split("=", 1)
                    if len(p) == 2: rec[p[0]] = p[1]
            if tag == "!re":    rows.append(rec)
            elif tag == "!done": break
            elif tag == "!trap": raise MikroTikAPIError(f"Trap: {rec.get('message','?')}")
        return rows

    def login(self, user, pw):
        # Kompatibel semua versi ROS:
        #   ROS 7.x          → tidak kirim challenge, plain-text langsung
        #   ROS 6.43 - 6.x   → kirim challenge tapi terima plain-text juga
        #   ROS < 6.43        → wajib MD5 challenge-response

        # ── Fase 1: kirim /login, baca sampai !done ──
        self._write(["/login"])
        challenge = None
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            tag = sentence[0]
            for w in sentence:
                if w.startswith("=ret="):
                    challenge = w[5:]
            if tag == "!done":
                break
            if tag == "!trap":
                raise MikroTikAPIError("Login gagal di fase awal")

        # ── Fase 2: coba plain-text dulu (ROS 6.43+ dan 7.x) ──
        self._write(["/login", f"=name={user}", f"=password={pw}"])
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            tag = sentence[0]
            if tag == "!done":
                return  # sukses dengan plain-text
            if tag == "!trap":
                # Plain-text gagal → coba MD5 jika ada challenge (ROS < 6.43)
                if not challenge:
                    raise MikroTikAPIError("Login gagal: username/password salah")
                break

        # ── Fase 3: fallback MD5 challenge-response (ROS < 6.43) ──
        import hashlib as _h
        ch  = bytes.fromhex(challenge)
        md5 = _h.md5()
        md5.update(b'\x00')
        md5.update(pw.encode("utf-8"))
        md5.update(ch)
        self._write(["/login", f"=name={user}", f"=response=00{md5.hexdigest()}"])
        while True:
            sentence = self._read_sentence()
            if not sentence:
                continue
            tag = sentence[0]
            if tag == "!done":
                return  # sukses dengan MD5
            if tag == "!trap":
                raise MikroTikAPIError("Login gagal: username/password salah")

    def query(self, cmd, **kw):
        self._write([cmd] + [f"={k}={v}" for k, v in kw.items()])
        return self._read_response()


# ══════════════════════════════════════════════
# CHECKER FUNCTIONS
# Signature: (api: MikroTikAPI, params: dict) → (bool, str)
# ══════════════════════════════════════════════

def cek_identity(api, p):
    exp = str(p.get("nama", "")).strip()
    rows = api.query("/system/identity/print")
    actual = rows[0].get("name", "").strip() if rows else ""
    ok = actual.lower() == exp.lower()
    return ok, f"identity='{actual}'" + ("" if ok else f" ≠ '{exp}'")

def cek_dhcp_client(api, p):
    iface = str(p.get("interface", "ether1"))
    exp_dis = str(p.get("disabled", "no")).lower()
    for r in api.query("/ip/dhcp-client/print"):
        if r.get("interface") == iface:
            dis = r.get("disabled", "true").lower()
            return dis == exp_dis, f"dhcp-client {iface} disabled={dis} status={r.get('status','?')}"
    return False, f"DHCP client '{iface}' tidak ditemukan"

def cek_ip_address(api, p):
    exp_addr  = str(p.get("address", "")).strip()
    exp_iface = str(p.get("interface", "")).strip()
    for r in api.query("/ip/address/print"):
        ia, aa, da = r.get("interface",""), r.get("address",""), r.get("disabled","false").lower()
        if ((not exp_iface or ia == exp_iface)
                and (exp_addr.lower() == "any" or aa == exp_addr)
                and da == "false"):
            return True, f"ip {aa} pada {ia} aktif"
    return False, f"IP '{exp_addr}' pada '{exp_iface}' tidak ditemukan"

def cek_nat_masquerade(api, p):
    exp_out = str(p.get("out_interface", "ether1")).strip()
    for r in api.query("/ip/firewall/nat/print"):
        if (r.get("chain") == "srcnat" and r.get("action") == "masquerade"
                and r.get("out-interface") == exp_out
                and r.get("disabled", "false").lower() == "false"):
            return True, f"srcnat masquerade out-interface={exp_out} aktif"
    return False, f"NAT masquerade out-interface='{exp_out}' tidak ditemukan"

def cek_static_route(api, p):
    exp_dst = str(p.get("dst_address", "")).strip()
    exp_gw  = str(p.get("gateway", "")).strip()
    for r in api.query("/ip/route/print"):
        dst, gw, dis = r.get("dst-address",""), r.get("gateway",""), r.get("disabled","false").lower()
        if ((not exp_dst or dst == exp_dst) and (not exp_gw or gw == exp_gw) and dis == "false"):
            return True, f"route {dst} via {gw}"
    return False, f"Route dst='{exp_dst}' gw='{exp_gw}' tidak ditemukan"

def cek_dns(api, p):
    exp_srv = str(p.get("servers", "")).strip()
    exp_rem = str(p.get("allow_remote_requests", "")).strip().lower()
    rows = api.query("/ip/dns/print")
    if not rows: return False, "Gagal baca DNS"
    r = rows[0]
    srv, rem = r.get("servers",""), r.get("allow-remote-requests","false").lower()
    ok = ((not exp_srv or exp_srv in srv) and (not exp_rem or rem == exp_rem))
    return ok, f"dns servers={srv} allow-remote={rem}"

def cek_bridge(api, p):
    name = str(p.get("name","")).strip()
    exp_members = [str(m).strip() for m in p.get("members", [])]
    bridges = api.query("/interface/bridge/print")
    if not any(b.get("name") == name for b in bridges):
        return False, f"Bridge '{name}' tidak ditemukan"
    if not exp_members:
        return True, f"Bridge '{name}' ada"
    ports = api.query("/interface/bridge/port/print")
    actual = {pp.get("interface") for pp in ports if pp.get("bridge") == name}
    missing = [m for m in exp_members if m not in actual]
    if missing: return False, f"Bridge '{name}' kekurangan member: {missing}"
    return True, f"Bridge '{name}' member={exp_members} OK"

def cek_service(api, p):
    name = str(p.get("name","")).strip()
    exp_dis = str(p.get("disabled","no")).lower()
    for r in api.query("/ip/service/print"):
        if r.get("name") == name:
            dis = r.get("disabled","true").lower()
            return dis == exp_dis, f"service {name} disabled={dis}"
    return False, f"Service '{name}' tidak ditemukan"

def cek_user(api, p):
    name = str(p.get("name","")).strip()
    exp_grp = str(p.get("group","")).strip()
    for r in api.query("/user/print"):
        if r.get("name") == name:
            grp = r.get("group","")
            ok = (not exp_grp) or grp == exp_grp
            return ok, f"user '{name}' group={grp}"
    return False, f"User '{name}' tidak ditemukan"

def cek_wireless(api, p):
    exp_iface = str(p.get("interface","wlan1")).strip()
    exp_ssid  = str(p.get("ssid","")).strip()
    exp_sec   = str(p.get("security_profile","")).strip()
    for r in api.query("/interface/wireless/print"):
        if r.get("name") != exp_iface: continue
        ssid, sec, dis = r.get("ssid",""), r.get("security-profile",""), r.get("disabled","false").lower()
        ok = ((not exp_ssid or ssid == exp_ssid) and (not exp_sec or sec == exp_sec) and dis == "false")
        return ok, f"wlan ssid='{ssid}' sec='{sec}'"
    return False, f"Wireless '{exp_iface}' tidak ditemukan"

CHECKER_MAP = {
    "identity":       cek_identity,
    "dhcp_client":    cek_dhcp_client,
    "ip_address":     cek_ip_address,
    "nat_masquerade": cek_nat_masquerade,
    "static_route":   cek_static_route,
    "dns":            cek_dns,
    "bridge":         cek_bridge,
    "service":        cek_service,
    "user":           cek_user,
    "wireless":       cek_wireless,
}


# ══════════════════════════════════════════════
# ENGINE KOREKSI
# ══════════════════════════════════════════════

def buat_koneksi(host, port, user, pw):
    api = MikroTikAPI(host, port)
    api.connect()
    api.login(user, pw)
    return api

def ambil_identity(host, port, user, pw):
    """Ambil nama identity router. Return str atau raise."""
    api = buat_koneksi(host, port, user, pw)
    try:
        rows = api.query("/system/identity/print")
        return rows[0].get("name", host).strip() if rows else host
    finally:
        api.close()

def koreksi_router(host, port, user, pw, soal_list):
    """
    Koreksi semua soal ke router di host:port.
    Return dict hasil lengkap.
    """
    api = None
    try:
        api = buat_koneksi(host, port, user, pw)
    except Exception as e:
        return {
            "status":  "error",
            "pesan":   str(e),
            "detail":  [],
            "nilai":   0,
            "token":   "",
            "waktu":   datetime.now().isoformat(),
        }

    detail      = []
    total_bobot = 0
    total_nilai = 0

    try:
        # Ambil identity dulu untuk nama siswa otomatis
        try:
            rows = api.query("/system/identity/print")
            identity = rows[0].get("name", host).strip() if rows else host
        except Exception:
            identity = host

        for soal in soal_list:
            tipe      = soal.get("tipe", "")
            deskripsi = soal.get("deskripsi", tipe)
            bobot     = int(soal.get("bobot", 1))
            params    = {k: v for k, v in soal.items()
                         if k not in ("nomor","tipe","deskripsi","bobot","_catatan")}
            total_bobot += bobot

            checker = CHECKER_MAP.get(tipe)
            if not checker:
                lulus, ket = False, f"Tipe '{tipe}' tidak dikenal"
            else:
                try:
                    lulus, ket = checker(api, params)
                except Exception as ex:
                    lulus, ket = False, f"Error: {ex}"

            poin = bobot if lulus else 0
            total_nilai += poin
            detail.append({
                "nomor":      soal.get("nomor", len(detail)+1),
                "tipe":       tipe,
                "deskripsi":  deskripsi,
                "bobot":      bobot,
                "nilai":      poin,
                "lulus":      lulus,
                "keterangan": ket,
            })
    finally:
        api.close()

    nilai_akhir = round(total_nilai / total_bobot * 100, 1) if total_bobot > 0 else 0
    token_src = (
        f"penilai-mt|{datetime.now().strftime('%Y-%m-%d')}"
        f"|{identity}|{host}|{nilai_akhir}"
        f"|{json.dumps(detail, sort_keys=True)}"
    )
    token = hashlib.sha256(token_src.encode()).hexdigest()[:12].upper()

    return {
        "status":       "ok",
        "identity":     identity,
        "host":         host,
        "nilai":        nilai_akhir,
        "total_bobot":  total_bobot,
        "total_nilai":  total_nilai,
        "total_benar":  sum(1 for d in detail if d["lulus"]),
        "total_soal":   len(soal_list),
        "token":        token,
        "waktu":        datetime.now().isoformat(),
        "detail":       detail,
    }


# ══════════════════════════════════════════════
# DIALOG: TAMBAH / EDIT SISWA
# ══════════════════════════════════════════════

class DialogSiswa(tk.Toplevel):
    """Dialog untuk tambah/edit entri siswa (IP + override soal)."""

    def __init__(self, parent, soal_template: list, data: dict = None):
        super().__init__(parent)
        self.title("Tambah Siswa" if data is None else "Edit Siswa")
        self.resizable(False, False)
        self.grab_set()
        self.result = None

        BG    = "#0f1117"
        PANEL = "#181c27"
        CARD  = "#1e2235"
        FG    = "#e2e8f0"
        ACC   = "#38bdf8"
        DIM   = "#64748b"

        self.configure(bg=BG)

        # ── Header ──
        tk.Label(self, text="KONFIGURASI SISWA", bg=BG, fg=ACC,
                 font=("Consolas", 12, "bold")).pack(pady=(16,4), padx=20, anchor="w")

        # ── IP & Koneksi ──
        frm = tk.Frame(self, bg=CARD, padx=12, pady=10)
        frm.pack(fill="x", padx=16, pady=4)

        def row(parent, lbl, var, r, placeholder=""):
            tk.Label(parent, text=lbl, bg=CARD, fg=DIM,
                     font=("Consolas", 9)).grid(row=r, column=0, sticky="w", pady=3)
            e = tk.Entry(parent, textvariable=var, bg="#252d40", fg=FG,
                         insertbackground=FG, relief="flat",
                         font=("Consolas", 10), width=24)
            e.grid(row=r, column=1, sticky="ew", padx=(8,0), pady=3)
            frm.columnconfigure(1, weight=1)
            return e

        self._ip   = tk.StringVar(value=data.get("host","") if data else "192.168.88.")
        self._port = tk.StringVar(value=str(data.get("port",8728)) if data else "8728")
        self._user = tk.StringVar(value=data.get("user","admin") if data else "admin")
        self._pw   = tk.StringVar(value=data.get("pw","") if data else "")

        row(frm, "IP Router",    self._ip,   0)
        row(frm, "Port API",     self._port, 1)
        row(frm, "Username",     self._user, 2)
        row(frm, "Password",     self._pw,   3)

        # ── Override soal per siswa ──
        tk.Label(self, text="PARAMETER SOAL (override per siswa)",
                 bg=BG, fg=ACC, font=("Consolas", 10, "bold")).pack(
                     pady=(12,2), padx=20, anchor="w")
        tk.Label(self, text="Kosongkan = ikut template global",
                 bg=BG, fg=DIM, font=("Consolas", 8)).pack(padx=20, anchor="w")

        # Scroll frame untuk daftar soal
        canvas_outer = tk.Frame(self, bg=BG)
        canvas_outer.pack(fill="both", expand=True, padx=16, pady=4)

        canvas = tk.Canvas(canvas_outer, bg=CARD, highlightthickness=0, height=220)
        vsb    = tk.Scrollbar(canvas_outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=CARD, padx=8, pady=8)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))

        # Ambil override yang sudah ada
        existing_overrides = {}
        if data and "soal_override" in data:
            for s in data["soal_override"]:
                existing_overrides[s["nomor"]] = s

        self._override_vars = {}   # nomor → {key → StringVar}

        for soal in soal_template:
            nomor   = soal.get("nomor", "?")
            tipe    = soal.get("tipe", "")
            deskripsi = soal.get("deskripsi", tipe)

            # Header soal
            hdr = tk.Frame(inner, bg="#252d40", pady=4, padx=8)
            hdr.pack(fill="x", pady=(6,2))
            tk.Label(hdr, text=f"[{nomor}] {deskripsi}",
                     bg="#252d40", fg=FG,
                     font=("Consolas", 9, "bold")).pack(side="left")
            tk.Label(hdr, text=tipe, bg="#252d40", fg=DIM,
                     font=("Consolas", 8)).pack(side="right")

            # Fields yang bisa di-override (semua params kecuali metadata)
            params_keys = [k for k in soal.keys()
                           if k not in ("nomor","tipe","deskripsi","bobot","_catatan")]
            self._override_vars[nomor] = {}
            ex_soal = existing_overrides.get(nomor, soal)

            for key in params_keys:
                pf = tk.Frame(inner, bg=CARD)
                pf.pack(fill="x", padx=4, pady=1)
                tk.Label(pf, text=f"  {key}:", bg=CARD, fg=DIM,
                         font=("Consolas", 9), width=20, anchor="e").pack(side="left")
                var = tk.StringVar(value=str(ex_soal.get(key, soal.get(key,""))))
                self._override_vars[nomor][key] = var
                tk.Entry(pf, textvariable=var, bg="#252d40", fg=FG,
                         insertbackground=FG, relief="flat",
                         font=("Consolas", 9), width=28).pack(side="left", padx=4)

        # ── Tombol ──
        bf = tk.Frame(self, bg=BG)
        bf.pack(fill="x", padx=16, pady=(8,16))

        tk.Button(bf, text="  Simpan  ", bg=ACC, fg="#0a0e1a",
                  font=("Consolas", 10, "bold"), relief="flat",
                  command=self._simpan).pack(side="right", padx=4)
        tk.Button(bf, text="  Batal  ", bg=CARD, fg=DIM,
                  font=("Consolas", 10), relief="flat",
                  command=self.destroy).pack(side="right")

        self.geometry("520x620")
        self.transient(parent)
        self.wait_window()

    def _simpan(self):
        try:
            port = int(self._port.get())
        except ValueError:
            messagebox.showerror("Error", "Port harus angka", parent=self)
            return
        ip = self._ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "IP tidak boleh kosong", parent=self)
            return

        # Bangun soal_override
        soal_override = []
        for nomor, kvars in self._override_vars.items():
            entry = {"nomor": nomor}
            for key, var in kvars.items():
                entry[key] = var.get()
            soal_override.append(entry)

        self.result = {
            "host":          ip,
            "port":          port,
            "user":          self._user.get().strip(),
            "pw":            self._pw.get(),
            "soal_override": soal_override,
        }
        self.destroy()


# ══════════════════════════════════════════════
# APLIKASI GUI UTAMA
# ══════════════════════════════════════════════

class PenilaiApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PENILAI MT — Koreksi MikroTik Guru")
        self.geometry("1200x720")
        self.minsize(950, 580)
        self.configure(bg="#0f1117")

        # State utama
        self._soal_template: list = []          # soal global dari JSON
        self._ujian_info:    dict = {}
        self._siswa:         list = []          # list dict {host,port,user,pw,soal_override,hasil}
        self._sel_idx:       int  = -1
        self._koreksi_running = False

        self._build_style()
        self._build_ui()

    # ── STYLE ─────────────────────────────────

    def _build_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        BG    = "#0f1117"
        PANEL = "#181c27"
        CARD  = "#1e2235"
        ACC   = "#38bdf8"
        GRN   = "#34d399"
        RED   = "#f87171"
        YLW   = "#fbbf24"
        FG    = "#e2e8f0"
        DIM   = "#64748b"
        SEL   = "#1e3a5f"
        self.C = dict(bg=BG, panel=PANEL, card=CARD, acc=ACC,
                      grn=GRN, red=RED, ylw=YLW, fg=FG, dim=DIM, sel=SEL)

        s.configure("TFrame",       background=BG)
        s.configure("P.TFrame",     background=PANEL)
        s.configure("C.TFrame",     background=CARD)
        s.configure("TLabel",       background=BG,    foreground=FG,  font=("Consolas",10))
        s.configure("H.TLabel",     background=PANEL, foreground=ACC, font=("Consolas",11,"bold"))
        s.configure("D.TLabel",     background=PANEL, foreground=DIM, font=("Consolas",9))
        s.configure("Cv.TLabel",    background=CARD,  foreground=FG,  font=("Consolas",10))
        s.configure("Num.TLabel",   background=CARD,  foreground=GRN, font=("Consolas",30,"bold"))
        s.configure("NumR.TLabel",  background=CARD,  foreground=RED, font=("Consolas",30,"bold"))
        s.configure("NumY.TLabel",  background=CARD,  foreground=YLW, font=("Consolas",30,"bold"))

        for nm, bg_c, fg_c in [
            ("A", ACC,  "#0a0e1a"),
            ("G", GRN,  "#0a0e1a"),
            ("R", RED,  "#fff"),
            ("W", YLW,  "#0a0e1a"),
            ("Gh", CARD, DIM),
        ]:
            s.configure(f"{nm}.TButton", background=bg_c, foreground=fg_c,
                        font=("Consolas",10,"bold"), relief="flat", padding=5)
            s.map(f"{nm}.TButton", background=[("active", bg_c)])

        s.configure("Treeview",
            background=PANEL, foreground=FG, fieldbackground=PANEL,
            rowheight=25, font=("Consolas",10), borderwidth=0)
        s.configure("Treeview.Heading",
            background=CARD, foreground=ACC,
            font=("Consolas",10,"bold"), relief="flat")
        s.map("Treeview",
            background=[("selected", SEL)],
            foreground=[("selected", FG)])
        s.configure("bar.Horizontal.TProgressbar",
            troughcolor=CARD, background=ACC)
        s.configure("TEntry",
            fieldbackground=CARD, foreground=FG,
            insertcolor=FG, relief="flat", font=("Consolas",10))

    # ── UI ────────────────────────────────────

    def _build_ui(self):
        C = self.C
        self.rowconfigure(1, weight=1)
        self.columnconfigure(1, weight=1)

        # Header
        hdr = tk.Canvas(self, height=52, bg="#090c14", highlightthickness=0)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew")
        hdr.create_text(18, 26, anchor="w",
            text="◈  PENILAI MT",
            fill=C["acc"], font=("Consolas",15,"bold"))
        hdr.create_text(205, 26, anchor="w",
            text="Koreksi Konfigurasi Router MikroTik — Akses Langsung dari Guru",
            fill=C["dim"], font=("Consolas",9))

        # Left panel
        left = ttk.Frame(self, style="P.TFrame", width=340)
        left.grid(row=1, column=0, sticky="nsew", padx=(8,4), pady=8)
        left.grid_propagate(False)
        left.columnconfigure(0, weight=1)
        self._build_left(left)

        # Right panel
        right = ttk.Frame(self, style="P.TFrame")
        right.grid(row=1, column=1, sticky="nsew", padx=(4,8), pady=8)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        self._build_right(right)

        # Statusbar
        self._sv = tk.StringVar(value="Muat file soal JSON, lalu tambah siswa.")
        sb = tk.Frame(self, bg="#090c14", height=24)
        sb.grid(row=2, column=0, columnspan=2, sticky="ew")
        tk.Label(sb, textvariable=self._sv, bg="#090c14", fg=C["dim"],
                 font=("Consolas",9), anchor="w").pack(side="left", padx=10)

    def _build_left(self, p):
        C = self.C
        r = 0

        # File soal
        ttk.Label(p, text="FILE SOAL", style="H.TLabel").grid(
            row=r, column=0, sticky="w", padx=12, pady=(12,4)); r+=1

        bf = ttk.Frame(p, style="P.TFrame")
        bf.grid(row=r, column=0, sticky="ew", padx=8, pady=(0,4)); r+=1
        bf.columnconfigure(0, weight=1)
        ttk.Button(bf, text="Muat Soal JSON…", style="A.TButton",
                   command=self._on_muat_soal).grid(row=0, column=0, sticky="ew")

        self._lbl_soal = ttk.Label(p, text="Belum ada soal dimuat",
                                    style="D.TLabel", wraplength=290, justify="left")
        self._lbl_soal.grid(row=r, column=0, sticky="w", padx=12, pady=(0,8)); r+=1

        ttk.Separator(p, orient="horizontal").grid(
            row=r, column=0, sticky="ew", padx=8, pady=4); r+=1

        # Daftar siswa
        ttk.Label(p, text="DAFTAR SISWA", style="H.TLabel").grid(
            row=r, column=0, sticky="w", padx=12, pady=(4,4)); r+=1

        tf = ttk.Frame(p, style="P.TFrame")
        tf.grid(row=r, column=0, sticky="nsew", padx=8); r+=1
        p.rowconfigure(r-1, weight=1)
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)

        self._tree = ttk.Treeview(tf, columns=("nama","ip","nilai","status"),
                                   show="headings", selectmode="browse")
        self._tree.heading("nama",   text="Nama (Identity)")
        self._tree.heading("ip",     text="IP Router")
        self._tree.heading("nilai",  text="Nilai")
        self._tree.heading("status", text="Status")
        self._tree.column("nama",   width=120)
        self._tree.column("ip",     width=100, anchor="center")
        self._tree.column("nilai",  width=50,  anchor="center")
        self._tree.column("status", width=65,  anchor="center")
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree.tag_configure("ok",     foreground=C["grn"])
        self._tree.tag_configure("gagal",  foreground=C["red"])
        self._tree.tag_configure("error",  foreground=C["dim"])
        self._tree.tag_configure("proses", foreground=C["ylw"])
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Tombol siswa
        brw = ttk.Frame(p, style="P.TFrame")
        brw.grid(row=r, column=0, sticky="ew", padx=8, pady=(4,0)); r+=1
        brw.columnconfigure((0,1,2), weight=1)
        ttk.Button(brw, text="+ Tambah", style="G.TButton",
                   command=self._on_tambah).grid(row=0, column=0, sticky="ew", padx=(0,2))
        ttk.Button(brw, text="✎ Edit",   style="Gh.TButton",
                   command=self._on_edit).grid(row=0, column=1, sticky="ew", padx=2)
        ttk.Button(brw, text="✕ Hapus",  style="R.TButton",
                   command=self._on_hapus).grid(row=0, column=2, sticky="ew", padx=(2,0))

        # Tombol aksi utama
        bra = ttk.Frame(p, style="P.TFrame")
        bra.grid(row=r, column=0, sticky="ew", padx=8, pady=8); r+=1
        bra.columnconfigure((0,1), weight=1)
        ttk.Button(bra, text="▶ Koreksi Dipilih", style="A.TButton",
                   command=self._on_koreksi_satu).grid(row=0, column=0, sticky="ew", padx=(0,2))
        ttk.Button(bra, text="▶▶ Koreksi Semua",  style="W.TButton",
                   command=self._on_koreksi_semua).grid(row=0, column=1, sticky="ew", padx=(2,0))

        self._prog = ttk.Progressbar(p, maximum=100, style="bar.Horizontal.TProgressbar")
        self._prog.grid(row=r, column=0, sticky="ew", padx=8, pady=(0,4)); r+=1

        ttk.Button(p, text="Export CSV", style="Gh.TButton",
                   command=self._on_export).grid(
                       row=r, column=0, sticky="ew", padx=8, pady=(0,10)); r+=1

    def _build_right(self, p):
        C = self.C

        # Kartu ringkasan
        kartu = ttk.Frame(p, style="C.TFrame")
        kartu.grid(row=0, column=0, sticky="ew", padx=12, pady=(12,4))
        kartu.columnconfigure(list(range(1,6)), weight=1)

        self._lbl_nilai = ttk.Label(kartu, text="—", style="Num.TLabel")
        self._lbl_nilai.grid(row=0, column=0, rowspan=2, padx=(16,24), pady=12)

        info_fields = [
            ("Nama",   "_li_nama"),
            ("IP",     "_li_ip"),
            ("Ujian",  "_li_ujian"),
            ("Token",  "_li_token"),
            ("Waktu",  "_li_waktu"),
        ]
        for col, (lbl, attr) in enumerate(info_fields, 1):
            ttk.Label(kartu, text=lbl, background=C["card"],
                      foreground=C["dim"], font=("Consolas",8)).grid(
                          row=0, column=col, sticky="w", padx=4)
            w = ttk.Label(kartu, text="—", style="Cv.TLabel")
            w.grid(row=1, column=col, sticky="w", padx=4, pady=(0,12))
            setattr(self, attr, w)

        # Tabel detail soal
        tf2 = ttk.Frame(p, style="P.TFrame")
        tf2.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
        tf2.rowconfigure(0, weight=1)
        tf2.columnconfigure(0, weight=1)

        cols = ("nomor","deskripsi","tipe","bobot","nilai","keterangan")
        self._tree_det = ttk.Treeview(tf2, columns=cols, show="headings",
                                       selectmode="none")
        self._tree_det.heading("nomor",     text="#")
        self._tree_det.heading("deskripsi", text="Deskripsi Soal")
        self._tree_det.heading("tipe",      text="Tipe Checker")
        self._tree_det.heading("bobot",     text="Bobot")
        self._tree_det.heading("nilai",     text="Nilai")
        self._tree_det.heading("keterangan",text="Keterangan")
        self._tree_det.column("nomor",      width=35,  anchor="center")
        self._tree_det.column("deskripsi",  width=200)
        self._tree_det.column("tipe",       width=115, anchor="center")
        self._tree_det.column("bobot",      width=55,  anchor="center")
        self._tree_det.column("nilai",      width=55,  anchor="center")
        self._tree_det.column("keterangan", width=320)

        vsb2 = ttk.Scrollbar(tf2, orient="vertical", command=self._tree_det.yview)
        self._tree_det.configure(yscrollcommand=vsb2.set)
        self._tree_det.grid(row=0, column=0, sticky="nsew")
        vsb2.grid(row=0, column=1, sticky="ns")
        self._tree_det.tag_configure("ok",    foreground=self.C["grn"])
        self._tree_det.tag_configure("gagal", foreground=self.C["red"])

    # ── LOGIC ─────────────────────────────────

    def _status(self, msg):
        self._sv.set(f"[{datetime.now().strftime('%H:%M:%S')}]  {msg}")

    def _on_muat_soal(self):
        path = filedialog.askopenfilename(
            title="Pilih file soal JSON",
            filetypes=[("JSON","*.json"),("Semua","*.*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self._ujian_info    = data.get("ujian", {})
            self._soal_template = data.get("soal", [])
            nama_ujian = self._ujian_info.get("nama", os.path.basename(path))
            self._lbl_soal.configure(
                text=f"✓ {nama_ujian}\n"
                     f"  {len(self._soal_template)} soal  |  "
                     f"kode: {self._ujian_info.get('kode','?')}")
            self._status(f"Soal dimuat: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal muat soal:\n{e}")

    def _soal_untuk_siswa(self, siswa: dict) -> list:
        """
        Gabungkan soal template dengan override per siswa.
        Override: nilai dari soal_override menimpa nilai template.
        """
        overrides = {s["nomor"]: s for s in siswa.get("soal_override", [])}
        hasil = []
        for soal in self._soal_template:
            merged = dict(soal)
            ov = overrides.get(soal.get("nomor"))
            if ov:
                for k, v in ov.items():
                    if k != "nomor" and v != "":
                        merged[k] = v
            hasil.append(merged)
        return hasil

    def _refresh_tree(self):
        sel_ip = None
        sel = self._tree.selection()
        if sel:
            sel_ip = self._tree.item(sel[0], "values")[1]

        for item in self._tree.get_children():
            self._tree.delete(item)

        for s in self._siswa:
            hasil = s.get("hasil", {})
            nama  = hasil.get("identity", s["host"]) if hasil else s["host"]
            nilai = str(hasil.get("nilai","—")) if hasil else "—"
            st    = hasil.get("status","—") if hasil else "pending"

            if st == "ok":
                tag = "ok" if float(hasil.get("nilai",0)) >= 60 else "gagal"
                st_txt = "✓ OK"
            elif st == "error":
                tag, st_txt = "error", "✗ Error"
            elif st == "proses":
                tag, st_txt = "proses", "…"
            else:
                tag, st_txt = "error", "pending"

            iid = self._tree.insert("", "end",
                values=(nama, s["host"], nilai, st_txt), tags=(tag,))
            if s["host"] == sel_ip:
                self._tree.selection_set(iid)

    def _on_select(self, _=None):
        sel = self._tree.selection()
        if not sel: return
        ip = self._tree.item(sel[0], "values")[1]
        idx = next((i for i,s in enumerate(self._siswa) if s["host"]==ip), -1)
        self._sel_idx = idx
        if idx >= 0:
            self._tampil_detail(self._siswa[idx])

    def _tampil_detail(self, siswa: dict):
        hasil = siswa.get("hasil", {})
        if not hasil:
            self._lbl_nilai.configure(text="—", style="Num.TLabel")
            for attr in ("_li_nama","_li_ip","_li_ujian","_li_token","_li_waktu"):
                getattr(self, attr).configure(text="—")
            for item in self._tree_det.get_children():
                self._tree_det.delete(item)
            return

        if hasil.get("status") == "error":
            self._lbl_nilai.configure(text="ERR", style="NumR.TLabel")
            self._li_nama.configure(text=siswa["host"])
            self._li_ip.configure(text=siswa["host"])
            self._li_ujian.configure(text=hasil.get("pesan","?"))
            self._li_token.configure(text="—")
            self._li_waktu.configure(text=hasil.get("waktu","—"))
            for item in self._tree_det.get_children():
                self._tree_det.delete(item)
            return

        nilai = hasil.get("nilai", 0)
        if nilai >= 75:   st = "Num.TLabel"
        elif nilai >= 60: st = "NumY.TLabel"
        else:             st = "NumR.TLabel"
        self._lbl_nilai.configure(text=str(nilai), style=st)
        self._li_nama.configure(text=hasil.get("identity","—"))
        self._li_ip.configure(text=hasil.get("host","—"))
        self._li_ujian.configure(text=self._ujian_info.get("nama","—"))
        self._li_token.configure(text=hasil.get("token","—"))
        self._li_waktu.configure(text=hasil.get("waktu","—")[:19])

        for item in self._tree_det.get_children():
            self._tree_det.delete(item)
        for d in hasil.get("detail",[]):
            tag = "ok" if d["lulus"] else "gagal"
            self._tree_det.insert("", "end", values=(
                d["nomor"], d["deskripsi"], d["tipe"],
                d["bobot"], d["nilai"], d["keterangan"]
            ), tags=(tag,))

    def _on_tambah(self):
        if not self._soal_template:
            messagebox.showwarning("Belum ada soal",
                "Muat file soal JSON dulu sebelum tambah siswa.")
            return
        dlg = DialogSiswa(self, self._soal_template)
        if dlg.result:
            # Cek duplikat IP
            if any(s["host"] == dlg.result["host"] for s in self._siswa):
                messagebox.showwarning("Duplikat",
                    f"IP {dlg.result['host']} sudah ada di daftar.")
                return
            self._siswa.append(dlg.result)
            self._refresh_tree()
            self._status(f"Siswa {dlg.result['host']} ditambahkan.")

    def _on_edit(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Info","Pilih siswa dulu."); return
        ip  = self._tree.item(sel[0], "values")[1]
        idx = next((i for i,s in enumerate(self._siswa) if s["host"]==ip), -1)
        if idx < 0: return
        dlg = DialogSiswa(self, self._soal_template, self._siswa[idx])
        if dlg.result:
            dlg.result["hasil"] = self._siswa[idx].get("hasil")
            self._siswa[idx] = dlg.result
            self._refresh_tree()

    def _on_hapus(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Info","Pilih siswa dulu."); return
        ip = self._tree.item(sel[0], "values")[1]
        if not messagebox.askyesno("Hapus", f"Hapus {ip} dari daftar?"):
            return
        self._siswa = [s for s in self._siswa if s["host"] != ip]
        self._refresh_tree()
        self._sel_idx = -1

    def _run_koreksi(self, targets: list):
        """Jalankan koreksi paralel untuk list index siswa."""
        if self._koreksi_running:
            messagebox.showinfo("Tunggu","Koreksi sedang berjalan."); return
        if not self._soal_template:
            messagebox.showwarning("Soal","Muat soal dulu."); return

        self._koreksi_running = True
        done_count = [0]
        total = len(targets)
        self._prog["value"] = 0

        def koreksi_satu(idx):
            s = self._siswa[idx]
            s["hasil"] = {"status":"proses"}
            self.after(0, self._refresh_tree)
            soal = self._soal_untuk_siswa(s)
            hasil = koreksi_router(s["host"], s["port"], s["user"], s["pw"], soal)
            s["hasil"] = hasil
            done_count[0] += 1
            pct = done_count[0] / total * 100
            self.after(0, lambda: self._prog.configure(value=pct))
            self.after(0, self._refresh_tree)
            if self._sel_idx == idx:
                self.after(0, lambda: self._tampil_detail(s))

        def _run():
            with ThreadPoolExecutor(max_workers=min(10, total)) as ex:
                list(as_completed({ex.submit(koreksi_satu, i) for i in targets}))
            self._koreksi_running = False
            self.after(0, lambda: self._status(
                f"Koreksi selesai: {total} router diproses."))

        threading.Thread(target=_run, daemon=True).start()
        self._status(f"Koreksi {total} router dimulai…")

    def _on_koreksi_satu(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Info","Pilih siswa dulu."); return
        ip  = self._tree.item(sel[0], "values")[1]
        idx = next((i for i,s in enumerate(self._siswa) if s["host"]==ip), -1)
        if idx >= 0:
            self._run_koreksi([idx])

    def _on_koreksi_semua(self):
        if not self._siswa:
            messagebox.showinfo("Info","Tambah siswa dulu."); return
        self._run_koreksi(list(range(len(self._siswa))))

    def _on_export(self):
        if not self._siswa:
            messagebox.showwarning("Kosong","Belum ada data."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile=f"nilai_mt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not path: return

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["Nama (Identity)","IP Router","Ujian","Nilai",
                        "Benar","Total Soal","Token","Waktu","Detail"])
            for s in self._siswa:
                h = s.get("hasil", {})
                if not h or h.get("status") != "ok":
                    w.writerow([s["host"],s["host"],"—","—","","","","",""])
                    continue
                detail_str = " | ".join(
                    f"[{d['nomor']}]{'OK' if d['lulus'] else 'NO'}"
                    f"({d['nilai']}/{d['bobot']}) {d['keterangan']}"
                    for d in h.get("detail",[])
                )
                w.writerow([
                    h.get("identity","—"), h.get("host","—"),
                    self._ujian_info.get("nama","—"),
                    h.get("nilai","—"),
                    h.get("total_benar",""), h.get("total_soal",""),
                    h.get("token",""), h.get("waktu","")[:19],
                    detail_str,
                ])
        self._status(f"CSV tersimpan: {path}")
        messagebox.showinfo("Export", f"Berhasil disimpan:\n{path}")


if __name__ == "__main__":
    PenilaiApp().mainloop()
