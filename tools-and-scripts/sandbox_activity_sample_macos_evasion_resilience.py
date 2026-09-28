#!/usr/bin/env python3
"""
Harmloses macOS Sandbox-Aktivitäts- und Evasion-Resilience-Sample.

Zweck:
- Die Sandbox selbst soll alle Aktivitäten protokollieren.
- Das Script erzeugt typische Signale, die bei Anti-Evasion-Prüfungen relevant sind.
- Es versucht NICHT, eine Sandbox zu umgehen.
- Es ändert sein Verhalten NICHT abhängig davon, ob VM/Sandbox-Indikatoren gefunden werden.
- Keine eigene Reporting-Datei.
- Am Ende jeder Funktion wird einmal der Funktionsname ausgegeben.
"""

import ctypes
import locale
import os
import platform
import random
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid
from pathlib import Path


TEST_DIR = Path(tempfile.gettempdir()) / "sandbox_activity_sample"
TEST_DIR.mkdir(parents=True, exist_ok=True)


def system_information():
    platform.platform()
    platform.machine()
    platform.processor()
    socket.gethostname()
    os.getcwd()
    os.environ.get("USER")
    os.cpu_count()

    subprocess.run(
        ["/usr/bin/whoami"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/bin/uname", "-a"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/sbin/system_profiler", "SPSoftwareDataType", "SPHardwareDataType"],
        capture_output=True,
        text=True,
        timeout=30
    )

    print("system_information")


def process_activity():
    subprocess.run(
        ["/bin/sh", "-c", "echo CHILD_PROCESS_TEST; whoami; uname -a"],
        capture_output=True,
        text=True,
        timeout=10
    )

    print("process_activity")


def process_tree_activity():
    subprocess.run(
        [
            "/bin/sh",
            "-c",
            "/bin/sh -c 'echo GRANDCHILD_PROCESS_TEST'"
        ],
        capture_output=True,
        text=True,
        timeout=15
    )

    print("process_tree_activity")


def thread_activity():
    def worker(number):
        path = TEST_DIR / f"thread_{number}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"thread {number}\n")
            f.flush()
            time.sleep(0.3)

    threads = []

    for i in range(4):
        thread = threading.Thread(
            target=worker,
            args=(i,),
            name=f"SandboxTestThread-{i}"
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("thread_activity")


def file_activity():
    file1 = TEST_DIR / "file_test.txt"
    file2 = TEST_DIR / "file_test_renamed.txt"

    with open(file1, "w", encoding="utf-8") as f:
        f.write("SANDBOX_FILE_WRITE_TEST\n")

    with open(file1, "a", encoding="utf-8") as f:
        f.write("SANDBOX_FILE_APPEND_TEST\n")

    with open(file1, "r", encoding="utf-8") as f:
        f.read()

    if file2.exists():
        file2.unlink()

    file1.rename(file2)

    with open(file2, "r+b") as f:
        f.seek(0)
        f.write(b"TEST")

    file2.unlink(missing_ok=True)

    print("file_activity")


def preference_activity():
    domain = "com.openai.sandboxactivitysample"

    subprocess.run(
        ["/usr/bin/defaults", "write", domain, "TestString", "SANDBOX_PREFERENCE_TEST"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/bin/defaults", "read", domain, "TestString"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/bin/defaults", "delete", domain],
        capture_output=True,
        text=True,
        timeout=10
    )

    print("preference_activity")


def process_service_queries():
    subprocess.run(
        ["/bin/ps", "-axo", "pid,ppid,user,command"],
        capture_output=True,
        text=True,
        timeout=15
    )

    subprocess.run(
        ["/bin/launchctl", "list"],
        capture_output=True,
        text=True,
        timeout=15
    )

    print("process_service_queries")


def library_activity():
    ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    print("library_activity")


def memory_activity():
    buffer1 = ctypes.create_string_buffer(b"SANDBOX_MEMORY_TEST")

    ctypes.memset(
        ctypes.addressof(buffer1),
        ord("A"),
        4
    )

    buffer2 = ctypes.create_string_buffer(4096)

    ctypes.memmove(
        ctypes.addressof(buffer2),
        ctypes.addressof(buffer1),
        min(ctypes.sizeof(buffer1), ctypes.sizeof(buffer2))
    )

    print("memory_activity")


def dns_activity():
    socket.gethostbyname("example.com")
    socket.getaddrinfo("example.org", 443, type=socket.SOCK_STREAM)
    print("dns_activity")


def tcp_activity():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        sock.connect(("example.com", 80))
        sock.sendall(
            b"HEAD / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Connection: close\r\n\r\n"
        )
        sock.recv(1024)
    finally:
        sock.close()

    print("tcp_activity")


def udp_activity():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b"SANDBOX_UDP_TEST", ("1.1.1.1", 53))
    sock.close()
    print("udp_activity")


def http_activity():
    request = urllib.request.Request(
        "http://example.com/?sandbox_test=http",
        headers={
            "User-Agent": "SandboxActivitySample/1.0",
            "X-Sandbox-Test": "HTTP_TEST"
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(512)
    except Exception:
        pass

    print("http_activity")


def https_activity():
    request = urllib.request.Request(
        "https://example.com/?sandbox_test=https",
        headers={
            "User-Agent": "SandboxActivitySample/1.0",
            "X-Sandbox-Test": "HTTPS_TEST"
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(512)
    except Exception:
        pass

    print("https_activity")


def tls_activity():
    context = ssl.create_default_context()

    try:
        with socket.create_connection(("example.com", 443), timeout=10) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname="example.com") as tls_socket:
                tls_socket.version()
                tls_socket.cipher()
                tls_socket.getpeercert()
    except Exception:
        pass

    print("tls_activity")


def local_socket_activity():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    port = listener.getsockname()[1]

    def server():
        connection, _ = listener.accept()
        connection.recv(128)
        connection.sendall(b"LOCAL_SOCKET_REPLY")
        connection.close()

    thread = threading.Thread(target=server, name="LocalSocketServer")
    thread.start()

    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.sendall(b"LOCAL_SOCKET_TEST")
    client.recv(128)
    client.close()

    thread.join()
    listener.close()

    print("local_socket_activity")


# -----------------------------
# Benigne Anti-Evasion-Resilience-Tests
# -----------------------------

def multi_clock_timing_activity():
    """
    Liest mehrere Zeitquellen vor und nach einem Sleep.
    Keine Verhaltensänderung abhängig vom Ergebnis.
    """
    time.time()
    time.monotonic()
    time.perf_counter()
    time.process_time()

    time.sleep(3)

    time.time()
    time.monotonic()
    time.perf_counter()
    time.process_time()

    print("multi_clock_timing_activity")


def delayed_execution_activity():
    """
    Kurze verzögerte Ausführung.
    Dient nur dazu zu prüfen, ob die Sandbox auch nach einer Wartezeit weiter aufzeichnet.
    """
    time.sleep(5)

    marker = TEST_DIR / "delayed_execution_marker.txt"
    marker.write_text("DELAYED_EXECUTION_TEST", encoding="utf-8")
    marker.unlink(missing_ok=True)

    print("delayed_execution_activity")


def jittered_timing_activity():
    """
    Mehrere kurze, zufällig variierte Wartezeiten.
    Kein Umgehungsversuch; die Funktion läuft immer vollständig durch.
    """
    for _ in range(5):
        time.sleep(random.uniform(0.2, 0.8))
        time.perf_counter()

    print("jittered_timing_activity")


def resource_profile_activity():
    """
    Fragt Ressourceninformationen ab, ohne daraus Entscheidungen abzuleiten.
    """
    os.cpu_count()
    platform.machine()

    subprocess.run(
        ["/usr/sbin/sysctl", "-n", "hw.memsize"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/sbin/sysctl", "-n", "hw.ncpu"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/sbin/sysctl", "-n", "hw.model"],
        capture_output=True,
        text=True,
        timeout=10
    )

    print("resource_profile_activity")


def virtualization_information_activity():
    """
    Liest allgemeine Virtualisierungs-/Hardwareinformationen.
    Das Ergebnis beeinflusst den Programmfluss NICHT.
    """
    commands = [
        ["/usr/sbin/sysctl", "-a"],
        ["/usr/sbin/system_profiler", "SPHardwareDataType"],
        ["/usr/sbin/system_profiler", "SPSoftwareDataType"]
    ]

    for command in commands:
        try:
            subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20
            )
        except Exception:
            pass

    print("virtualization_information_activity")


def locale_timezone_activity():
    """
    Liest Sprache, Locale und Zeitzoneninformationen.
    """
    locale.getlocale()
    locale.getpreferredencoding(False)
    time.tzname

    os.environ.get("LANG")
    os.environ.get("LC_ALL")
    os.environ.get("LC_CTYPE")
    os.environ.get("TZ")

    subprocess.run(
        ["/usr/bin/defaults", "read", "-g", "AppleLocale"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/bin/defaults", "read", "-g", "AppleLanguages"],
        capture_output=True,
        text=True,
        timeout=10
    )

    print("locale_timezone_activity")


def identity_profile_activity():
    """
    Liest Host-/User-/Geräteinformationen für Randomization-Vergleiche.
    Mehrere Sandbox-Runs können anschließend manuell verglichen werden.
    """
    socket.gethostname()
    os.environ.get("USER")
    os.environ.get("HOME")
    uuid.getnode()

    subprocess.run(
        ["/usr/sbin/scutil", "--get", "ComputerName"],
        capture_output=True,
        text=True,
        timeout=10
    )

    subprocess.run(
        ["/usr/sbin/scutil", "--get", "LocalHostName"],
        capture_output=True,
        text=True,
        timeout=10
    )

    print("identity_profile_activity")


def software_environment_activity():
    """
    Fragt installierte/aktive Softwareumgebung read-only ab.
    Keine Suche nach konkreten Sandbox-Produkten.
    """
    subprocess.run(
        ["/bin/ps", "-axo", "pid,user,command"],
        capture_output=True,
        text=True,
        timeout=15
    )

    subprocess.run(
        ["/bin/launchctl", "list"],
        capture_output=True,
        text=True,
        timeout=15
    )

    subprocess.run(
        ["/usr/sbin/system_profiler", "SPApplicationsDataType"],
        capture_output=True,
        text=True,
        timeout=30
    )

    print("software_environment_activity")


def filesystem_environment_activity():
    """
    Read-only Abfragen typischer Nutzerverzeichnisse.
    """
    paths = [
        Path.home(),
        Path.home() / "Desktop",
        Path.home() / "Documents",
        Path.home() / "Downloads",
        Path("/Applications")
    ]

    for path in paths:
        try:
            list(path.iterdir())[:20]
        except Exception:
            pass

    print("filesystem_environment_activity")


def user_interaction_activity():
    """
    Öffnet ein einfaches natives macOS-Dialogfenster, falls osascript verfügbar ist.
    Der Test läuft auch weiter, wenn keine Interaktion erfolgt.
    """
    try:
        subprocess.run(
            [
                "/usr/bin/osascript",
                "-e",
                'display dialog "Harmloser Sandbox-Test" buttons {"OK"} '
                'default button "OK" giving up after 5'
            ],
            capture_output=True,
            text=True,
            timeout=10
        )
    except Exception:
        pass

    print("user_interaction_activity")


def repeated_network_activity():
    """
    Mehrere gleichartige, harmlose HTTPS-Anfragen mit kurzem Abstand.
    Damit kann man prüfen, ob die Sandbox periodische Netzwerkaktivität erkennt.
    Kein C2 und keine Befehlsübertragung.
    """
    for i in range(3):
        try:
            request = urllib.request.Request(
                f"https://example.com/?periodic_test={i}",
                headers={
                    "User-Agent": "SandboxActivitySample-Periodic/1.0"
                }
            )

            with urllib.request.urlopen(request, timeout=8) as response:
                response.read(128)
        except Exception:
            pass

        if i < 2:
            time.sleep(2)

    print("repeated_network_activity")


def environment_consistency_activity():
    """
    Wiederholt dieselben read-only Abfragen, um zu sehen,
    ob die Sandbox während eines Laufs inkonsistente Werte liefert.
    """
    for _ in range(3):
        socket.gethostname()
        os.cpu_count()
        platform.machine()
        time.time()
        time.monotonic()
        time.sleep(0.5)

    print("environment_consistency_activity")


def main():
    system_information()

    process_activity()
    process_tree_activity()
    thread_activity()

    file_activity()
    preference_activity()

    process_service_queries()
    library_activity()
    memory_activity()

    dns_activity()
    tcp_activity()
    udp_activity()
    http_activity()
    https_activity()
    tls_activity()
    local_socket_activity()

    # Anti-Evasion-Resilience
    multi_clock_timing_activity()
    delayed_execution_activity()
    jittered_timing_activity()
    resource_profile_activity()
    virtualization_information_activity()
    locale_timezone_activity()
    identity_profile_activity()
    software_environment_activity()
    filesystem_environment_activity()
    user_interaction_activity()
    repeated_network_activity()
    environment_consistency_activity()

    print("ALL_TESTS_FINISHED")


if __name__ == "__main__":
    main()
