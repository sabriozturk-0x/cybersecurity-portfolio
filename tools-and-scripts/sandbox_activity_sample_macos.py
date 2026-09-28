#!/usr/bin/env python3
"""
Harmloses Sandbox-Aktivitäts-Sample für macOS.

Zweck:
Die Sandbox selbst soll Prozess-, Datei-, Netzwerk-, Speicher-,
System- und Library-Aktivitäten protokollieren.

Kein eigenes Reporting.
Keine JSON-/CSV-Ausgabe.
Am Ende jeder Funktion wird einmal der Funktionsname ausgegeben.
"""

import ctypes
import os
import platform
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
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


def directory_activity():
    directory = TEST_DIR / "directory_test"
    nested = directory / "nested"

    directory.mkdir(exist_ok=True)
    nested.mkdir(exist_ok=True)

    test_file = nested / "inside.txt"
    test_file.write_text("DIRECTORY_TEST", encoding="utf-8")

    test_file.unlink(missing_ok=True)
    nested.rmdir()
    directory.rmdir()

    print("directory_activity")


def preference_activity():
    """
    macOS-Äquivalent zu einer harmlosen Registry-/Preference-Aktion.
    Schreibt einen temporären User-Preference-Key und löscht ihn danach.
    """
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
    buffer1 = ctypes.create_string_buffer(
        b"SANDBOX_MEMORY_TEST"
    )

    ctypes.memset(
        ctypes.addressof(buffer1),
        ord("A"),
        4
    )

    buffer2 = ctypes.create_string_buffer(4096)

    ctypes.memmove(
        ctypes.addressof(buffer2),
        ctypes.addressof(buffer1),
        min(
            ctypes.sizeof(buffer1),
            ctypes.sizeof(buffer2)
        )
    )

    print("memory_activity")


def dns_activity():
    socket.gethostbyname("example.com")

    socket.getaddrinfo(
        "example.org",
        443,
        type=socket.SOCK_STREAM
    )

    print("dns_activity")


def tcp_activity():
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

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
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.sendto(
        b"SANDBOX_UDP_TEST",
        ("1.1.1.1", 53)
    )

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
        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:
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
        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:
            response.read(512)
    except Exception:
        pass

    print("https_activity")


def tls_activity():
    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            ("example.com", 443),
            timeout=10
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname="example.com"
            ) as tls_socket:

                tls_socket.version()
                tls_socket.cipher()
                tls_socket.getpeercert()

    except Exception:
        pass

    print("tls_activity")


def local_socket_activity():
    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    listener.bind(
        ("127.0.0.1", 0)
    )

    listener.listen(1)
    port = listener.getsockname()[1]

    def server():
        connection, _ = listener.accept()
        connection.recv(128)
        connection.sendall(b"LOCAL_SOCKET_REPLY")
        connection.close()

    thread = threading.Thread(
        target=server,
        name="LocalSocketServer"
    )

    thread.start()

    client = socket.create_connection(
        ("127.0.0.1", port),
        timeout=5
    )

    client.sendall(b"LOCAL_SOCKET_TEST")
    client.recv(128)
    client.close()

    thread.join()
    listener.close()

    print("local_socket_activity")


def timing_activity():
    time.time()
    time.monotonic()
    time.perf_counter()
    time.process_time()

    time.sleep(2)

    time.time()
    time.monotonic()
    time.perf_counter()
    time.process_time()

    print("timing_activity")


def environment_activity():
    for key in [
        "PATH",
        "TMPDIR",
        "HOME",
        "USER",
        "SHELL",
        "LANG"
    ]:
        os.environ.get(key)

    print("environment_activity")


def macos_system_queries():
    commands = [
        ["/usr/sbin/system_profiler", "SPHardwareDataType"],
        ["/usr/sbin/system_profiler", "SPNetworkDataType"],
        ["/usr/sbin/system_profiler", "SPSoftwareDataType"],
        ["/usr/bin/sw_vers"],
        ["/usr/sbin/scutil", "--get", "ComputerName"],
        ["/usr/sbin/scutil", "--get", "LocalHostName"],
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

    print("macos_system_queries")


def main():
    system_information()
    environment_activity()

    process_activity()
    process_tree_activity()
    thread_activity()

    file_activity()
    directory_activity()
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

    timing_activity()
    macos_system_queries()

    print("ALL_TESTS_FINISHED")


if __name__ == "__main__":
    main()
