


from __future__ import annotations

import argparse
import curses
import locale
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

APP = "Wifi_Scanner"
VERSION = "2.1"

BAND_2_4 = "2.4G"
BAND_5 = "5G"
BAND_6 = "6G"
BAND_UNKNOWN = "?"


class Color(IntEnum):
    GOOD = 1
    FAIR = 2
    BAD = 3
    BAR = 4
    HEAD = 5
    ACTIVE = 6


@dataclass(frozen=True)
class Network:
    bssid: str
    essid: str
    channel: int
    freq: int
    rate: int
    estimated: bool
    signal: int
    security: str
    active: bool

    @property
    def band(self) -> str:
        return freq_to_band(self.freq)

    @property
    def dbm(self) -> int:
        return pct_to_dbm(self.signal)

    @property
    def speed_label(self) -> str:
        if not self.rate:
            return "?"
        return f"{'~' if self.estimated else ''}{self.rate} Mbps"


Backend = Callable[[], List[Network]]


class Selected(NamedTuple):
    name: str
    scan: Backend


def run(cmd: List[str], timeout: int = 25) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def freq_to_channel(freq: int) -> int:
    if freq == 2484:
        return 14
    if 2400 <= freq < 2500:
        return (freq - 2407) // 5
    if 5000 <= freq < 5950:
        return (freq - 5000) // 5
    if 5950 <= freq <= 7125:
        return (freq - 5950) // 5
    return 0


def freq_to_band(freq: int) -> str:
    if freq == 0:
        return BAND_UNKNOWN
    if freq < 3000:
        return BAND_2_4
    if freq < 5950:
        return BAND_5
    return BAND_6


def channel_to_freq(channel: int) -> int:
    if channel == 14:
        return 2484
    if 1 <= channel < 14:
        return 2407 + channel * 5
    return 5000 + channel * 5


def dbm_to_pct(dbm: float) -> int:
    return max(0, min(100, int(2 * (dbm + 100))))


def pct_to_dbm(pct: int) -> int:
    return int(pct / 2 - 100)


NUMBER = re.compile(r"[\d.]+")


def to_int(text: str) -> int:
    found = NUMBER.search(text)
    return int(float(found.group())) if found else 0


def split_terse(line: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    escaped = False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def scan_nmcli() -> List[Network]:
    out = run(
        [
            "nmcli", "-t", "-f", "IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
            "dev", "wifi", "list", "--rescan", "yes",
        ]
    )
    networks: List[Network] = []
    for line in out.splitlines():
        parts = split_terse(line)
        if len(parts) < 8:
            continue
        in_use, bssid, ssid, chan, freq, rate, signal, security = parts[:8]
        networks.append(
            Network(
                bssid=bssid.upper(),
                essid=ssid or "<hidden>",
                channel=to_int(chan),
                freq=to_int(freq),
                rate=to_int(rate),
                estimated=False,
                signal=to_int(signal),
                security="Open" if security in ("", "--") else security,
                active=in_use.strip() == "*",
            )
        )
    return networks


def wifi_interface() -> Optional[str]:
    found = re.search(r"Interface (\S+)", run(["iw", "dev"]))
    return found.group(1) if found else None


def iw_security(block: str) -> str:
    if "WPA3" in block or "SAE" in block:
        return "WPA3"
    if "RSN:" in block:
        return "WPA2"
    if "WPA:" in block:
        return "WPA"
    if "Privacy" in block:
        return "WEP"
    return "Open"


def iw_rate(block: str) -> Tuple[int, bool]:
    for marker, rate in (("HE capabilities", 600), ("VHT capabilities", 433), ("HT capabilities", 150)):
        if marker in block:
            return rate, True
    rates = [
        float(token.rstrip("*"))
        for line in re.findall(r"upported rates: (.*)", block)
        for token in line.split()
    ]
    return (int(max(rates)) if rates else 0), False


def scan_iw() -> List[Network]:
    iface = wifi_interface()
    if not iface:
        return []
    out = run(["iw", "dev", iface, "scan"])
    networks: List[Network] = []
    for block in re.split(r"(?m)^BSS ", out)[1:]:
        freq = re.search(r"freq: (\d+)", block)
        signal = re.search(r"signal: (-?[\d.]+) dBm", block)
        ssid = re.search(r"SSID: (.*)", block)
        if not (freq and signal):
            continue
        f = int(freq.group(1))
        rate, estimated = iw_rate(block)
        networks.append(
            Network(
                bssid=block[:17].upper(),
                essid=(ssid.group(1) if ssid else "") or "<hidden>",
                channel=freq_to_channel(f),
                freq=f,
                rate=rate,
                estimated=estimated,
                signal=dbm_to_pct(float(signal.group(1))),
                security=iw_security(block),
                active="associated" in block.partition("\n")[0],
            )
        )
    return networks


RADIO_SPEED = {
    "802.11b": 11,
    "802.11a": 54,
    "802.11g": 54,
    "802.11n": 300,
    "802.11ac": 866,
    "802.11ax": 1201,
    "802.11be": 2882,
}


def scan_netsh() -> List[Network]:
    out = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    rows: List[Dict[str, Any]] = []
    ssid = auth = ""
    current: Optional[Dict[str, Any]] = None
    for raw in out.splitlines():
        line = raw.strip()
        m = re.match(r"SSID \d+ : (.*)", line)
        if m:
            ssid, auth, current = m.group(1).strip(), "", None
            continue
        if line.startswith("Authentication"):
            auth = line.split(":", 1)[1].strip()
            continue
        m = re.match(r"BSSID \d+\s*: (.*)", line)
        if m:
            current = {
                "bssid": m.group(1).strip(),
                "ssid": ssid,
                "auth": auth,
                "signal": 0,
                "radio": "",
                "chan": 0,
            }
            rows.append(current)
            continue
        if current is None or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key == "Signal":
            current["signal"] = to_int(value)
        elif key == "Radio type":
            current["radio"] = value
        elif key == "Channel":
            current["chan"] = to_int(value)
    return [
        Network(
            bssid=row["bssid"].upper(),
            essid=row["ssid"] or "<hidden>",
            channel=row["chan"],
            freq=channel_to_freq(row["chan"]),
            rate=RADIO_SPEED.get(row["radio"], 0),
            estimated=True,
            signal=row["signal"],
            security="Open" if row["auth"].lower() == "open" else row["auth"],
            active=False,
        )
        for row in rows
    ]


def pick_backend() -> Optional[Selected]:
    if platform.system() == "Windows":
        return Selected("netsh", scan_netsh)
    if shutil.which("nmcli"):
        return Selected("nmcli", scan_nmcli)
    if shutil.which("iw"):
        return Selected("iw (root)", scan_iw)
    return None


class Scanner(threading.Thread):
    def __init__(self, scan: Backend, interval: int) -> None:
        super().__init__(daemon=True)
        self.scan = scan
        self.interval = interval
        self.networks: List[Network] = []
        self.previous: Dict[str, int] = {}
        self.paused = False
        self.scanning = False
        self.last = 0.0
        self.running = True
        self.lock = threading.Lock()
        self.kick = threading.Event()

    def run(self) -> None:
        while self.running:
            if not self.paused or self.kick.is_set():
                self.scanning = True
                fresh = self.scan()
                with self.lock:
                    self.previous = {n.bssid: n.signal for n in self.networks}
                    self.networks = fresh
                    self.last = time.time()
                self.scanning = False
            self.kick.clear()
            self.kick.wait(self.interval)

    def snapshot(self) -> Tuple[List[Network], Dict[str, int]]:
        with self.lock:
            return list(self.networks), dict(self.previous)

    def stop(self) -> None:
        self.running = False
        self.kick.set()


SORT_KEYS: Dict[str, Callable[[Network], Any]] = {
    "signal": lambda n: n.signal,
    "essid": lambda n: n.essid.lower(),
    "channel": lambda n: n.channel,
    "speed": lambda n: n.rate,
    "bssid": lambda n: n.bssid,
}
SORT_NAMES = list(SORT_KEYS)
DEFAULT_REVERSE = {"signal", "speed"}


@dataclass
class ViewState:
    sort_index: int = 0
    reverse: bool = True
    scroll: int = 0

    @property
    def sort_name(self) -> str:
        return SORT_NAMES[self.sort_index]


def put(win: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    height, width = win.getmaxyx()
    if not 0 <= y < height or x >= width:
        return
    limit = max(0, width - x - (1 if y == height - 1 else 0))
    try:
        win.addstr(y, x, text[:limit], attr)
    except curses.error:
        pass


def signal_color(pct: int) -> int:
    level = Color.GOOD if pct >= 70 else Color.FAIR if pct >= 40 else Color.BAD
    return curses.color_pair(int(level))


def draw_title(win: Any, sc: Scanner, backend: str, count: int) -> None:
    width = win.getmaxyx()[1]
    ago = f"{int(time.time() - sc.last)}s ago" if sc.last else "never"
    state = "SCANNING" if sc.scanning else "PAUSED" if sc.paused else "LIVE"
    text = (
        f" {APP} v{VERSION} "
        f" {backend} | {count} networks | every {sc.interval}s | last {ago} | {state} "
    )
    put(win, 0, 0, text.ljust(width), curses.color_pair(int(Color.BAR)) | curses.A_BOLD)


def draw_table(
    win: Any,
    sc: Scanner,
    nets: List[Network],
    prev: Dict[str, int],
    view: ViewState,
    table_h: int,
) -> None:
    width = win.getmaxyx()[1]
    c_bssid, c_ch, c_band, c_spd, c_sig, c_sec = 17, 4, 5, 11, 15, 12
    c_essid = max(10, width - (c_bssid + c_ch + c_band + c_spd + c_sig + c_sec + 9))
    arrow = "▼" if view.reverse else "▲"

    def head(label: str, key: str, size: int) -> str:
        return (label + (arrow if key == view.sort_name else "")).ljust(size)

    header = " ".join(
        (
            "",
            head("ESSID", "essid", c_essid),
            head("BSSID", "bssid", c_bssid),
            head("CH", "channel", c_ch),
            "BAND".ljust(c_band),
            head("SPEED", "speed", c_spd),
            head("SIGNAL", "signal", c_sig),
            "SECURITY".ljust(c_sec),
        )
    )
    put(win, 1, 0, header.ljust(width), curses.color_pair(int(Color.HEAD)) | curses.A_BOLD)

    if not nets:
        message = (
            "Scanning..."
            if sc.scanning or not sc.last
            else "No networks found (is WiFi on? for 'iw' backend run as root)"
        )
        put(win, 3, 2, message, curses.A_DIM)

    for i, net in enumerate(nets[view.scroll : view.scroll + table_h]):
        y = 2 + i
        attr = curses.color_pair(int(Color.ACTIVE)) | curses.A_BOLD if net.active else 0
        x = 0
        put(win, y, x, ("●" if net.active else " ") + net.essid[:c_essid].ljust(c_essid), attr)
        x += c_essid + 2
        put(win, y, x, net.bssid.ljust(c_bssid), attr)
        x += c_bssid + 1
        put(win, y, x, str(net.channel).ljust(c_ch), attr)
        x += c_ch + 1
        put(win, y, x, net.band.ljust(c_band), attr)
        x += c_band + 1
        put(win, y, x, net.speed_label.ljust(c_spd), attr)
        x += c_spd + 1
        bars = int(net.signal / 100 * 8 + 0.5)
        color = signal_color(net.signal)
        put(win, y, x, "█" * bars + "░" * (8 - bars), color)
        old = prev.get(net.bssid)
        trend = " " if old is None or old == net.signal else "↑" if net.signal > old else "↓"
        put(win, y, x + 9, f"{net.dbm:>4}dBm{trend}", color)
        x += c_sig + 1
        sec_attr = curses.color_pair(int(Color.BAD)) if net.security == "Open" else 0
        put(win, y, x, net.security[:c_sec].ljust(c_sec), sec_attr)


def draw_usage(win: Any, nets: List[Network], top: int, rows: int) -> None:
    width = win.getmaxyx()[1]
    put(win, top, 0, " Channel usage ".ljust(width), curses.color_pair(int(Color.HEAD)) | curses.A_BOLD)
    usage: Dict[Tuple[str, int], List[int]] = defaultdict(list)
    for net in nets:
        usage[(net.band, net.channel)].append(net.signal)
    cell_w = 28
    per_row = max(1, width // cell_w)
    cells = sorted(usage.items())[: per_row * (rows - 1)]
    for i, ((band, channel), signals) in enumerate(cells):
        y, x = top + 1 + i // per_row, (i % per_row) * cell_w + 1
        count = len(signals)
        put(win, y, x, f"{band:>4} ch{channel:<3}")
        put(win, y, x + 10, ("█" * min(count, 10)).ljust(10), signal_color(max(signals)))
        put(win, y, x + 21, f" {count}")


def draw(win: Any, sc: Scanner, backend: str, view: ViewState) -> None:
    win.erase()
    height, width = win.getmaxyx()
    nets, prev = sc.snapshot()
    nets.sort(key=SORT_KEYS[view.sort_name], reverse=view.reverse)

    panel_h = 6 if height >= 26 else 0
    table_h = max(1, height - 3 - panel_h)
    view.scroll = max(0, min(view.scroll, max(0, len(nets) - table_h)))

    draw_title(win, sc, backend, len(nets))
    draw_table(win, sc, nets, prev, view, table_h)
    if panel_h:
        draw_usage(win, nets, height - 1 - panel_h, panel_h)

    footer = " q quit  s sort  v reverse  r rescan  +/- interval  space pause  ↑↓ scroll "
    put(win, height - 1, 0, footer.ljust(width), curses.color_pair(int(Color.BAR)))
    win.refresh()


def handle_key(key: int, sc: Scanner, view: ViewState, height: int) -> bool:
    if key in (27, ord("q"), ord("Q")):
        return False
    if key in (ord("s"), ord("S")):
        view.sort_index = (view.sort_index + 1) % len(SORT_NAMES)
        view.reverse = view.sort_name in DEFAULT_REVERSE
    elif key in (ord("v"), ord("V")):
        view.reverse = not view.reverse
    elif key in (ord("r"), ord("R")):
        sc.kick.set()
    elif key == ord(" "):
        sc.paused = not sc.paused
    elif key in (ord("+"), ord("=")):
        sc.interval = min(120, sc.interval + 1)
    elif key in (ord("-"), ord("_")):
        sc.interval = max(1, sc.interval - 1)
    elif key == curses.KEY_UP:
        view.scroll -= 1
    elif key == curses.KEY_DOWN:
        view.scroll += 1
    elif key == curses.KEY_PPAGE:
        view.scroll -= height // 2
    elif key == curses.KEY_NPAGE:
        view.scroll += height // 2
    return True


def tui(stdscr: Any, backend: Selected, interval: int) -> None:
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(int(Color.GOOD), curses.COLOR_GREEN, -1)
    curses.init_pair(int(Color.FAIR), curses.COLOR_YELLOW, -1)
    curses.init_pair(int(Color.BAD), curses.COLOR_RED, -1)
    curses.init_pair(int(Color.BAR), curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(int(Color.HEAD), curses.COLOR_CYAN, -1)
    curses.init_pair(int(Color.ACTIVE), curses.COLOR_MAGENTA, -1)
    stdscr.timeout(200)

    scanner = Scanner(backend.scan, interval)
    scanner.start()
    view = ViewState()
    try:
        while True:
            draw(stdscr, scanner, backend.name, view)
            key = stdscr.getch()
            if not handle_key(key, scanner, view, stdscr.getmaxyx()[0]):
                break
    finally:
        scanner.stop()


def print_once(scan: Backend) -> None:
    print(f"{'ESSID':<28} {'BSSID':<17} {'CH':>3} {'BAND':<4} {'SPEED':>10} {'SIGNAL':>7}  SECURITY")
    for n in sorted(scan(), key=lambda net: -net.signal):
        print(
            f"{n.essid[:28]:<28} {n.bssid:<17} {n.channel:>3} {n.band:<4} "
            f"{n.speed_label:>10} {n.dbm:>4}dBm  {n.security}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=f"{APP} - btop-style WiFi scanner")
    parser.add_argument("-i", "--interval", type=int, default=3, help="scan interval in seconds")
    parser.add_argument("--once", action="store_true", help="scan once and print a plain table")
    args = parser.parse_args()

    backend = pick_backend()
    if backend is None:
        sys.exit("No scan backend found. Install NetworkManager (nmcli) or 'iw' (run as root).")
    if args.once:
        print_once(backend.scan)
        return

    locale.setlocale(locale.LC_ALL, "")
    try:
        curses.wrapper(tui, backend, max(1, args.interval))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
