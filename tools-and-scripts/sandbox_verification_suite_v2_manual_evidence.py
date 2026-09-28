#!/usr/bin/env python3
"""
Sandbox Verification Suite v1
=============================

Harmloser, reproduzierbarer Test für Sandbox-Reporting.

Ziele:
- Prozess-/Thread-/Datei-/Registry-/Netzwerk-/TLS-/DNS-Sichtbarkeit prüfen
- Reporting-Tiefe vergleichen
- Timing-/Umgebungsinformationen dokumentieren
- statisch sichtbare Marker, Strings, Kompression und hohe Entropie erzeugen
- wiederholbare Resultate in JSON schreiben

NICHT enthalten:
- Prozessinjektion
- Shellcode-Ausführung
- direkte Syscalls / Hook-Bypass
- Kernel-Treiber / Rootkits
- Credential Access
- Persistenz
- Security-Bypass
- Exploits
- echter C2-Verkehr

Das Sample verändert sein Verhalten NICHT abhängig davon, ob es in einer VM/Sandbox läuft.
"""

from __future__ import annotations

import base64
import ctypes
import datetime as dt
import gzip
import hashlib
import json
import locale
import mmap
import os
import platform
import random
import secrets
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path

VERSION = "2.0-manual-evidence"
RUN_ID = str(uuid.uuid4())
START = time.time()
RESULTS = {"suite_version": VERSION, "run_id": RUN_ID, "tests": {}}
ROOT = Path(tempfile.gettempdir()) / f"sandbox_verification_{RUN_ID[:8]}"
ROOT.mkdir(parents=True, exist_ok=True)

# Static-analysis markers. These are DATA only, never executed.
STATIC_MARKERS = {
    "yara_marker": "SANDBOX_VERIFICATION_YARA_MARKER_4F0D9C7A",
    "sigma_marker": "SANDBOX_VERIFICATION_SIGMA_MARKER",
    "suricata_marker": "SANDBOX_VERIFICATION_SURICATA_MARKER",
    "ioc_test_domain": "example.com",
    "ioc_test_url": "https://example.com/sandbox-verification",
    "fake_c2_label": "BENIGN_C2_SIMULATION_ONLY",
    "api_names": [
        "CreateFileW", "ReadFile", "WriteFile", "CreateProcessW",
        "RegCreateKeyExW", "RegSetValueExW", "connect", "send", "recv"
    ],
}

def add(name, value, ok=True, note=None):
    RESULTS["tests"][name] = {"ok": bool(ok), "value": value}
    if note:
        RESULTS["tests"][name]["note"] = note
    print(f"[SVT|{name}|{'OK' if ok else 'INFO'}] {value}")

def safe_run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"returncode": p.returncode, "stdout": p.stdout[-12000:], "stderr": p.stderr[-4000:]}
    except Exception as e:
        return {"error": repr(e)}

def system_environment():
    add("system.platform", platform.platform())
    add("system.machine", platform.machine())
    add("system.python", sys.version)
    add("system.hostname", socket.gethostname())
    add("system.user", os.environ.get("USERNAME") or os.environ.get("USER"))
    add("system.cwd", os.getcwd())
    add("system.cpu_count", os.cpu_count())
    add("system.locale", locale.getlocale())
    add("system.timezone", list(time.tzname))
    add("system.utc_now", dt.datetime.now(dt.timezone.utc).isoformat())
    add("system.local_now", dt.datetime.now().astimezone().isoformat())
    add("system.env_subset", {k: os.environ.get(k) for k in ["PATH","TEMP","TMP","HOME","USERPROFILE","COMPUTERNAME"]})

    mac = uuid.getnode()
    mac_s = ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    add("system.mac", mac_s)

    if os.name == "nt":
        add("windows.systeminfo", safe_run(["cmd.exe", "/c", "systeminfo"]))
        add("windows.whoami", safe_run(["cmd.exe", "/c", "whoami /all"]))
        add("windows.drivers_readonly", safe_run(["cmd.exe", "/c", "driverquery /fo csv"]))
        add("windows.services_readonly", safe_run(["cmd.exe", "/c", "sc query type= service state= all"]))
        add("windows.bios_readonly", safe_run([
            "powershell.exe","-NoProfile","-Command",
            "Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,SerialNumber | ConvertTo-Json -Compress"
        ]))
        add("windows.computersystem_readonly", safe_run([
            "powershell.exe","-NoProfile","-Command",
            "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,HypervisorPresent | ConvertTo-Json -Compress"
        ]))
    else:
        for p in ["/sys/class/dmi/id/sys_vendor","/sys/class/dmi/id/product_name","/sys/class/dmi/id/bios_vendor"]:
            try:
                add("linux.dmi." + Path(p).name, Path(p).read_text(errors="ignore").strip())
            except Exception as e:
                add("linux.dmi." + Path(p).name, repr(e), ok=False)

def static_and_files():
    marker = json.dumps(STATIC_MARKERS, indent=2).encode()
    p = ROOT / "static_markers.json"
    p.write_bytes(marker)
    add("file.created", str(p))
    add("file.sha256", hashlib.sha256(marker).hexdigest())

    renamed = ROOT / "static_markers_renamed.json"
    p.rename(renamed)
    add("file.renamed", str(renamed))
    _ = renamed.read_bytes()
    add("file.read", len(_))

    # High-entropy benign data, never executed.
    entropy_blob = secrets.token_bytes(64 * 1024)
    ep = ROOT / "high_entropy_test.bin"
    ep.write_bytes(entropy_blob)
    add("static.high_entropy_blob", {"path": str(ep), "size": ep.stat().st_size})

    # Compressed/packed benign payload.
    benign_payload = (b"BENIGN_UNPACKING_TEST|" * 4096) + marker
    gz = gzip.compress(benign_payload, compresslevel=9)
    gp = ROOT / "benign_payload.gz"
    gp.write_bytes(gz)
    unpacked = gzip.decompress(gz)
    add("static.compression_unpacking", {
        "compressed": len(gz), "uncompressed": len(unpacked),
        "sha256": hashlib.sha256(unpacked).hexdigest()
    })

    zp = ROOT / "benign_archive.zip"
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("embedded/marker.txt", marker)
        z.writestr("embedded/script.js", 'console.log("BENIGN_EMBEDDED_SCRIPT");')
        z.writestr("embedded/script.ps1", 'Write-Output "BENIGN_EMBEDDED_SCRIPT"')
    add("static.embedded_objects_archive", str(zp))

    # Base64/obfuscation-like DATA, decoded but not executed.
    b64 = base64.b64encode(b"BENIGN_DEOBFUSCATION_TEST|" + marker).decode()
    decoded = base64.b64decode(b64)
    add("static.base64_decode", {"encoded_len": len(b64), "decoded_sha256": hashlib.sha256(decoded).hexdigest()})

def child_worker(depth=1):
    if depth == 1:
        # Child launches grandchild to create a clear process tree.
        cmd = [sys.executable, __file__, "--child", "2"]
        add("process.child_launch", safe_run(cmd))
    else:
        print("GRANDCHILD_OK", os.getpid())

def process_threads_handles():
    add("process.pid", os.getpid())
    add("process.ppid", os.getppid())
    add("process.argv", sys.argv)

    # Child process with explicit command-line arguments.
    cmd = [sys.executable, __file__, "--child", "1", "--marker", "COMMAND_LINE_VISIBLE_TEST"]
    add("process.tree", safe_run(cmd))

    # Several threads with names.
    thread_results = []
    def worker(i):
        f = open(ROOT / f"thread_{i}.txt", "w", encoding="utf-8")
        f.write(f"thread={i}\n")
        f.flush()
        time.sleep(0.25 + i * 0.05)
        thread_results.append({"thread": i, "native_id": getattr(threading.current_thread(), "native_id", None)})
        f.close()

    threads = [threading.Thread(target=worker, args=(i,), name=f"SandboxTestThread-{i}") for i in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    add("process.threads", thread_results)

    # Benign open handles: file + local socket.
    with open(ROOT / "handle_test.txt", "w", encoding="utf-8") as f:
        f.write("HANDLE_TEST")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        add("process.handle_like_objects", {"file_fd": f.fileno(), "socket_fd": s.fileno()})
        s.close()

    # DLL/module load using only a standard OS library.
    try:
        if os.name == "nt":
            lib = ctypes.WinDLL("kernel32.dll")
            add("process.dll_load", "kernel32.dll")
        else:
            lib = ctypes.CDLL(None)
            add("process.shared_library_load", "process-global libc/runtime")
    except Exception as e:
        add("process.library_load_error", repr(e), ok=False)

def benign_registry():
    if os.name != "nt":
        add("registry.skipped", "not Windows", ok=False)
        return
    try:
        import winreg
        key_path = r"Software\SandboxVerificationSuite"
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, "Marker", 0, winreg.REG_SZ, "BENIGN_SANDBOX_TEST")
        value, _ = winreg.QueryValueEx(key, "Marker")
        add("registry.create_set_read", value)
        winreg.DeleteValue(key, "Marker")
        winreg.CloseKey(key)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        add("registry.cleanup", "completed")
    except Exception as e:
        add("registry.error", repr(e), ok=False)

def timing_tests():
    clocks = {
        "time": time.time,
        "monotonic": time.monotonic,
        "perf_counter": time.perf_counter,
        "process_time": time.process_time,
    }
    before = {k: fn() for k, fn in clocks.items()}
    wall_before = dt.datetime.now(dt.timezone.utc)
    requested = 3.0
    time.sleep(requested)
    after = {k: fn() for k, fn in clocks.items()}
    wall_after = dt.datetime.now(dt.timezone.utc)
    deltas = {k: after[k] - before[k] for k in before}
    deltas["utc_wall"] = (wall_after - wall_before).total_seconds()
    add("timing.sleep_requested_seconds", requested)
    add("timing.clock_deltas", deltas)
    add("timing.consistency_spread", max(deltas.values()) - min(deltas.values()))

def dns_tests():
    domains = ["example.com", "example.org", "iana.org"]
    out = {}
    for d in domains:
        try:
            out[d] = socket.getaddrinfo(d, 443, type=socket.SOCK_STREAM)
        except Exception as e:
            out[d] = repr(e)
    add("dns.queries_responses", out)

def tls_https_tests():
    host = "example.com"
    port = 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                add("tls.metadata", {
                    "version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "server_hostname_sni": host,
                    "peer": ssock.getpeername(),
                    "cert_subject": cert.get("subject"),
                    "cert_issuer": cert.get("issuer"),
                    "cert_notAfter": cert.get("notAfter"),
                })
    except Exception as e:
        add("tls.error", repr(e), ok=False)

    url = "https://example.com/?sandbox_verification=1"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "SandboxVerificationSuite/1.0",
            "X-Sandbox-Verification": RUN_ID,
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(4096)
            add("http.https_request", {
                "url": url, "method": "GET", "status": resp.status,
                "headers": dict(resp.headers.items()),
                "body_prefix_sha256": hashlib.sha256(body).hexdigest(),
                "body_prefix_len": len(body),
            })
    except Exception as e:
        add("http.https_error", repr(e), ok=False)

def beacon_pattern_test():
    # Benign periodic traffic to example.com; intended only to see whether
    # the sandbox labels periodicity/beacon-like patterns. No C2 commands/data.
    observations = []
    for i in range(3):
        t0 = time.time()
        try:
            url = f"https://example.com/?benign_beacon={i}&run={RUN_ID}"
            req = urllib.request.Request(url, headers={"User-Agent": "SandboxVerificationSuite-BenignBeacon/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                observations.append({"i": i, "status": resp.status, "t": t0})
        except Exception as e:
            observations.append({"i": i, "error": repr(e), "t": t0})
        if i < 2:
            time.sleep(2)
    add("network.benign_periodic_https", observations, note="Kein echter C2; nur periodisches HTTPS zu example.com.")

def doh_test():
    # Harmloser DNS-over-HTTPS Lookup für example.com.
    url = "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/dns-json",
            "User-Agent": "SandboxVerificationSuite/1.0",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(8192)
            add("doh.lookup", {"status": resp.status, "content_type": resp.headers.get("Content-Type"), "bytes": len(body)})
    except Exception as e:
        add("doh.error", repr(e), ok=False)

def dot_test():
    # Harmloser DoT-Verbindungsaufbau; sendet absichtlich keine komplexen Inhalte.
    # Der TLS-Handshake zu Port 853 genügt häufig als DoT-Verkehrssignal.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("1.1.1.1", 853), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname="cloudflare-dns.com") as s:
                add("dot.tls_handshake", {"version": s.version(), "cipher": s.cipher(), "peer": s.getpeername()})
    except Exception as e:
        add("dot.error", repr(e), ok=False)

def udp_443_probe():
    # UDP/443 erzeugt Netzwerkverkehr, ist aber KEIN vollständiger QUIC-Handshake.
    # Im Report muss daher "UDP/443 sichtbar" von "QUIC erkannt" getrennt werden.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        payload = b"BENIGN_UDP443_VISIBILITY_TEST"
        s.sendto(payload, ("1.1.1.1", 443))
        add("quic.udp443_probe", {"bytes": len(payload), "target": "1.1.1.1:443"}, note="Nur UDP/443-Sichtbarkeit, kein vollständiger QUIC-Test.")
        s.close()
    except Exception as e:
        add("quic.udp443_error", repr(e), ok=False)

def local_network_test():
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        got = {}

        def server():
            conn, addr = listener.accept()
            data = conn.recv(128)
            conn.sendall(b"LOCAL_SERVER_OK")
            got["server_received"] = data.decode(errors="replace")
            conn.close()
            listener.close()

        th = threading.Thread(target=server, name="LocalNetworkServer")
        th.start()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
            c.sendall(b"LOCAL_CLIENT_TEST")
            reply = c.recv(128)
        th.join()
        add("network.local_client_server", {"port": port, "reply": reply.decode(), **got})
    except Exception as e:
        add("network.local_error", repr(e), ok=False)

def memory_tests():
    # Lokale, harmlose Speicheroperationen. Keine fremden Prozesse, keine Ausführung.
    data = b"BENIGN_MEMORY_MARKER|" + STATIC_MARKERS["yara_marker"].encode()
    buf = ctypes.create_string_buffer(data)
    add("memory.local_buffer_address", hex(ctypes.addressof(buf)))
    add("memory.local_buffer_size", ctypes.sizeof(buf))

    mm = mmap.mmap(-1, 4096)
    mm.write(b"BENIGN_MMAP_MARKER")
    mm.seek(0)
    readback = mm.read(18)
    add("memory.mmap_rw", readback.decode(errors="replace"))
    mm.close()

    # Benigner "dump fixture": nur eigener statischer Datenpuffer, KEIN Prozessdump.
    dump = ROOT / "benign_memory_fixture.bin"
    dump.write_bytes((data + b"\x00") * 512)
    add("memory.benign_fixture_file", str(dump), note="Kein echter Process Memory Dump.")

def interaction_test():
    # Optional kleine GUI. Keine automatisierten Klicks.
    try:
        import tkinter as tk
        root = tk.Tk()
        root.title("Sandbox Verification – Benign Interaction Test")
        clicked = {"value": False}
        def click():
            clicked["value"] = True
            root.destroy()
        tk.Label(root, text="Harmloser Sandbox-Test: Button anklicken").pack(padx=20, pady=10)
        tk.Button(root, text="Testklick", command=click).pack(padx=20, pady=10)
        root.after(5000, root.destroy)
        root.mainloop()
        add("interaction.gui_button_clicked", clicked["value"])
    except Exception as e:
        add("interaction.gui_unavailable", repr(e), ok=False)

def fingerprint():
    fp = {
        "hostname": socket.gethostname(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "mac": uuid.getnode(),
        "timezone": list(time.tzname),
        "locale": locale.getlocale(),
        "cpu_count": os.cpu_count(),
    }
    add("environment.fingerprint", fp)
    (ROOT / "environment_fingerprint.json").write_text(json.dumps(fp, indent=2, default=str), encoding="utf-8")

def save():
    RESULTS["duration_seconds"] = time.time() - START
    RESULTS["output_dir"] = str(ROOT)
    out = ROOT / "sandbox_verification_results.json"
    out.write_text(json.dumps(RESULTS, indent=2, default=str), encoding="utf-8")

    # Kompakte Referenz für die manuelle Protokollierung. Die Sandbox muss diese
    # Datei nicht auswerten; sie hilft nur dabei, Report-Ereignisse dem Sample
    # eindeutig zuzuordnen.
    manifest = ROOT / "manual_evidence_manifest.csv"
    with manifest.open("w", encoding="utf-8", newline="") as f:
        f.write("event_id;sample_result;manuelle_auswertung\n")
        for event_id, item in RESULTS["tests"].items():
            value = json.dumps(item.get("value"), ensure_ascii=False, default=str).replace(";", ",").replace("\n", " ")
            f.write(f"{event_id};{value};\n")

    print("\nRESULT FILE:", out)
    print("MANUAL EVIDENCE MANIFEST:", manifest)
    print("\nFür die Bewertungsmatrix je Kriterium eintragen:")
    print("  JA | <konkret im Sandbox-Report sichtbar>")
    print("  TEIL | <nur teilweise sichtbar>")
    print("  NEIN | <Testaktion lief, aber Report zeigt es nicht>")
    print("  NP | nicht geprüft")

def main():
    print("=" * 72)
    print("Sandbox Verification Suite v1 – BENIGN")
    print("Run ID:", RUN_ID)
    print("=" * 72)
    system_environment()
    static_and_files()
    process_threads_handles()
    benign_registry()
    memory_tests()
    timing_tests()
    local_network_test()
    dns_tests()
    tls_https_tests()
    beacon_pattern_test()
    doh_test()
    dot_test()
    udp_443_probe()
    fingerprint()
    if "--no-gui" not in sys.argv:
        interaction_test()
    save()

if __name__ == "__main__":
    if "--child" in sys.argv:
        try:
            idx = sys.argv.index("--child")
            depth = int(sys.argv[idx + 1])
        except Exception:
            depth = 2
        child_worker(depth)
    else:
        main()
