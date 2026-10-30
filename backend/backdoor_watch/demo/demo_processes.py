"""Fictional processes and sockets for demo mode. Addresses use documentation ranges (RFC 5737)."""

import time

from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.process import ProcessInfo, SignatureInfo

USER = r"C:\Users\demo"
_NOW = time.time()
_MS = SignatureInfo(status="Valid", subject="CN=Microsoft Windows, O=Microsoft Corporation")


def _proc(pid: int, ppid: int, name: str, exe: str, cmdline: str, age_s: int, sig: SignatureInfo | None,
          mem: float = 40, cpu: float = 0.3) -> ProcessInfo:
    return ProcessInfo(pid=pid, ppid=ppid, name=name, exe=exe, cmdline=cmdline, username=r"DEMO\analyst",
                       create_time=_NOW - age_s, cpu_percent=cpu, memory_mb=mem, signature=sig)


def _signed(company: str) -> SignatureInfo:
    return SignatureInfo(status="Valid", subject=f"CN={company}, O={company}")


def demo_processes() -> dict[int, ProcessInfo]:
    processes = [
        _proc(1100, 4, "explorer.exe", r"C:\Windows\explorer.exe", r"C:\Windows\explorer.exe", 90000, _MS, 120),
        _proc(2210, 1100, "Code.exe", rf"{USER}\AppData\Local\Programs\Microsoft VS Code\Code.exe",
              "Code.exe", 7200, _signed("Microsoft Corporation"), 410, 2.1),
        _proc(2290, 2210, "cmd.exe", r"C:\Windows\System32\cmd.exe",
              r"cmd.exe /d /s /c node server\index.js", 1500, _MS, 4),
        _proc(2301, 2290, "node.exe", r"C:\Program Files\nodejs\node.exe",
              rf"node {USER}\Downloads\interview-task\server\index.js", 1490, _signed("OpenJS Foundation"), 96, 1.4),
        _proc(3377, 2301, "python.exe", rf"{USER}\.pyp\python.exe", rf"{USER}\.pyp\python.exe {USER}\.n2\pay",
              1480, None, 38, 0.8),
        _proc(3412, 1, "AnyDesk.exe", rf"{USER}\AppData\Roaming\AnyDesk\AnyDesk.exe", "AnyDesk.exe --service",
              1470, _signed("philandro Software GmbH"), 22),
        _proc(4100, 1100, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe",
              5000, _signed("Google LLC"), 310, 3.2),
        _proc(4410, 1100, "Teams.exe", rf"{USER}\AppData\Local\Microsoft\Teams\Teams.exe", "Teams.exe",
              6000, _signed("Microsoft Corporation"), 280, 1.1),
        _proc(5001, 1100, "Slack.exe", rf"{USER}\AppData\Local\slack\slack.exe", "slack.exe", 6200,
              _signed("Slack Technologies"), 240, 0.9),
        _proc(5200, 1100, "postgres.exe", r"C:\Program Files\PostgreSQL\18\bin\postgres.exe", "postgres.exe", 80000,
              SignatureInfo(status="NotSigned"), 55),
        _proc(5400, 1100, "node.exe", rf"{USER}\Projects\my-app\node_modules\.bin\node.exe",
              rf"node {USER}\Projects\my-app\node_modules\vite\bin\vite.js", 3000, _signed("OpenJS Foundation"), 130),
        _proc(6001, 1100, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              r"powershell.exe -NoExit -File C:\Tools\flockion-backdoor-watch\start.ps1", 600, _MS, 70),
        _proc(6050, 6001, "python.exe", r"C:\Tools\flockion-backdoor-watch\backend\.venv\Scripts\python.exe",
              r"python.exe run.py", 590, _signed("Python Software Foundation"), 90, 1.8),
        _proc(7000, 4, "svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs", 90000, _MS, 30),
    ]
    return {p.pid: p for p in processes}


DEMO_OWN_PIDS = frozenset({6001, 6050})
C2_IP, SECOND_IP = "203.0.113.45", "198.51.100.77"


def _conn(pid: int, name: str, remote: str, port: int, host: str | None, out: int, inb: int,
          local_port: int) -> Connection:
    return Connection(protocol="tcp", family="ipv4", local_ip="192.168.1.20", local_port=local_port, remote_ip=remote,
                      remote_port=port, state="ESTABLISHED", pid=pid, process_name=name, remote_host=host,
                      is_external=True, bytes_out=out, bytes_in=inb)


def _listener(pid: int, name: str, ip: str, port: int) -> Connection:
    return Connection(protocol="tcp", family="ipv4", local_ip=ip, local_port=port, remote_ip=None, remote_port=None,
                      state="LISTEN", pid=pid, process_name=name, is_external=False)


def demo_connections() -> list[Connection]:
    return [
        _conn(3377, "python.exe", C2_IP, 1224, None, 18_400_000, 92_000, 51234),
        _conn(2301, "node.exe", SECOND_IP, 8080, None, 640_000, 21_000, 51310),
        _conn(3412, "AnyDesk.exe", "192.0.2.14", 443, "relay-eu.example.net", 2_100_000, 3_900_000, 51402),
        _conn(4100, "chrome.exe", "142.250.185.14", 443, "www.google.com", 3_200_000, 18_500_000, 51500),
        _conn(4100, "chrome.exe", "151.101.1.69", 443, "cdn.example-news.com", 410_000, 6_200_000, 51501),
        _conn(4410, "Teams.exe", "52.112.0.5", 443, "teams.microsoft.com", 1_800_000, 2_400_000, 51600),
        _conn(5001, "Slack.exe", "34.200.10.9", 443, "wss-primary.slack.com", 220_000, 610_000, 51700),
        _conn(2210, "Code.exe", "13.107.42.14", 443, "vscode.dev", 90_000, 260_000, 51800),
        _listener(5200, "postgres.exe", "0.0.0.0", 5432),
        _listener(5400, "node.exe", "0.0.0.0", 5173),
        _listener(3412, "AnyDesk.exe", "0.0.0.0", 7070),
        _listener(6050, "python.exe", "127.0.0.1", 8765),
        _listener(7000, "svchost.exe", "0.0.0.0", 135),
    ]
