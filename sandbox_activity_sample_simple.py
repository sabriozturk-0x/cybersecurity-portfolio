#!/usr/bin/env python3
"""
Harmloses Sandbox-Aktivitäts-Sample.

Zweck:
Die Sandbox selbst soll Netzwerk-, Prozess-, Datei-, Registry-,
Speicher- und Systemaktivitäten protokollieren.

Das Script erstellt KEIN eigenes Reporting und KEINE Ergebnisdateien
außer den bewusst erzeugten Testdateien.

Am Ende jeder Funktion wird genau einmal der Funktionsname ausgegeben.
"""

import ctypes
import os
import platform
import socket
import ssl
import subprocess
import sys
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
    os.environ.get("USERNAME")
    os.environ.get("USER")
    os.cpu_count()

    if os.name == "nt":
        subprocess.run(
            ["cmd.exe", "/c", "whoami"],
            capture_output=True,
            text=True,
            timeout=10
        )
        subprocess.run(
            ["cmd.exe", "/c", "ver"],
            capture_output=True,
            text=True,
            timeout=10
        )
        subprocess.run(
            ["cmd.exe", "/c", "systeminfo"],
            capture_output=True,
            text=True,
            timeout=20
        )

    print("system_information")


def process_activity():
    if os.name == "nt":
        subprocess.run(
            ["cmd.exe", "/c", "echo CHILD_PROCESS_TEST && whoami"],
            capture_output=True,
            text=True,
            timeout=10
        )
    else:
        subprocess.run(
            ["/bin/sh", "-c", "echo CHILD_PROCESS_TEST; whoami; uname -a"],
            capture_output=True,
            text=True,
            timeout=10
        )

    print("process_activity")


def process_tree_activity():
    if os.name == "nt":
        subprocess.run(
            [
                "cmd.exe",
                "/c",
                'powershell.exe -NoProfile -Command "Write-Output GRANDCHILD_PROCESS_TEST"'
            ],
            capture_output=True,
            text=True,
            timeout=15
        )
    else:
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
        t = threading.Thread(
            target=worker,
            args=(i,),
            name=f"SandboxTestThread-{i}"
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

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
    directory.mkdir(exist_ok=True)

    nested = directory / "nested"
    nested.mkdir(exist_ok=True)

    test_file = nested / "inside.txt"
    test_file.write_text("DIRECTORY_TEST", encoding="utf-8")

    test_file.unlink(missing_ok=True)
    nested.rmdir()
    directory.rmdir()

    print("directory_activity")


def registry_activity():
    if os.name == "nt":
        import winreg

        key_path = r"Software\SandboxActivitySample"

        key = winreg.CreateKey(
            winreg.HKEY_CURRENT_USER,
            key_path
        )

        winreg.SetValueEx(
            key,
            "TestString",
            0,
            winreg.REG_SZ,
            "SANDBOX_REGISTRY_TEST"
        )

        winreg.SetValueEx(
            key,
            "TestNumber",
            0,
            winreg.REG_DWORD,
            12345
        )

        winreg.QueryValueEx(
            key,
            "TestString"
        )

        winreg.DeleteValue(
            key,
            "TestString"
        )

        winreg.DeleteValue(
            key,
            "TestNumber"
        )

        winreg.CloseKey(key)

        winreg.DeleteKey(
            winreg.HKEY_CURRENT_USER,
            key_path
        )

    print("registry_activity")


def service_driver_queries():
    if os.name == "nt":
        subprocess.run(
            ["cmd.exe", "/c", "sc query"],
            capture_output=True,
            text=True,
            timeout=20
        )

        subprocess.run(
            ["cmd.exe", "/c", "driverquery"],
            capture_output=True,
            text=True,
            timeout=20
        )

    print("service_driver_queries")


def dll_library_activity():
    if os.name == "nt":
        ctypes.WinDLL("kernel32.dll")
        ctypes.WinDLL("user32.dll")
        ctypes.WinDLL("advapi32.dll")
        ctypes.WinDLL("ws2_32.dll")
    else:
        ctypes.CDLL(None)

    print("dll_library_activity")


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
        sock.connect(
            ("example.com", 80)
        )

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

        connection.sendall(
            b"LOCAL_SOCKET_REPLY"
        )

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

    client.sendall(
        b"LOCAL_SOCKET_TEST"
    )

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
    keys = [
        "PATH",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "USERNAME",
        "COMPUTERNAME"
    ]

    for key in keys:
        os.environ.get(key)

    print("environment_activity")


def windows_system_queries():
    if os.name == "nt":
        commands = [
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_ComputerSystem | "
                "Select Manufacturer,Model,HypervisorPresent"
            ],
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_BIOS | "
                "Select Manufacturer,SMBIOSBIOSVersion,SerialNumber"
            ],
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_NetworkAdapter | "
                "Select Name,MACAddress"
            ]
        ]

        for command in commands:
            subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20
            )

    print("windows_system_queries")


def main():
    system_information()
    environment_activity()

    process_activity()
    process_tree_activity()
    thread_activity()

    file_activity()
    directory_activity()

    registry_activity()
    service_driver_queries()
    dll_library_activity()

    memory_activity()

    dns_activity()
    tcp_activity()
    udp_activity()
    http_activity()
    https_activity()
    tls_activity()
    local_socket_activity()

    timing_activity()
    windows_system_queries()

    print("ALL_TESTS_FINISHED")


if __name__ == "__main__":
    main()
