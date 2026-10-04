#!/usr/bin/env python3
"""
Wifi_Scanner - a btop-style live WiFi network scanner for the terminal.

Shows every nearby network with ESSID, BSSID, channel, band, speed, signal
and security, plus a channel congestion panel.

Backends (auto-detected):
  * Linux   : nmcli (NetworkManager)  -> no root needed
              iw dev <iface> scan     -> fallback, needs root
  * Windows : netsh wlan show networks mode=bssid  (pip install windows-curses)

Keys:
  q / Esc  quit            s  cycle sort column     v  reverse sort
  r        rescan now      +/-  scan interval       space  pause
  Up/Down/PgUp/PgDn  scroll
"""
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

APP = "Wifi_Scanner"
VERSION = "1.0"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def run(cmd, timeout=25):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def freq_to_channel(f):
    if f == 2484:
        return 14
    if 2400 <= f < 2500:
        return (f - 2407) // 5
    if 5000 <= f < 5950:
        return (f - 5000) // 5
    if 5950 <= f <= 7125:
        return (f - 5950) // 5
    return 0


def freq_to_band(f):
    if f < 3000:
        return "2.4G"
    if f < 5950:
        return "5G"
    return "6G"


def channel_to_freq(ch):
    if 1 <= ch <= 14:
        return 2484 if ch == 14 else 2407 + ch * 5
    return 5000 + ch * 5  # good enough for band detection on 5 GHz


def dbm_to_pct(dbm):
    return max(0, min(100, int(2 * (dbm + 100))))


def pct_to_dbm(pct):
    return int(pct / 2 - 100)


def split_terse(line):
    """Split an `nmcli -t` line on ':' honouring '\\:' escapes."""
    parts, cur, esc = [], "", False
    for ch in line:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def make_net(bssid, essid, channel, freq, rate, est, signal, security, active):
    return {
        "bssid": bssid.upper(),
        "essid": essid or "<hidden>",
        "channel": channel,
        "freq": freq,
        "band": freq_to_band(freq) if freq else "?",
        "rate": rate,
        "est": est,
        "signal": signal,
        "dbm": pct_to_dbm(signal),
        "security": security or "Open",
        "active": active,
    }


# --------------------------------------------------------------------------
# scan backends
# --------------------------------------------------------------------------
def scan_nmcli():
    out = run(["nmcli", "-t", "-f", "IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,SECURITY",
               "dev", "wifi", "list", "--rescan", "yes"])
    nets = []
    for line in out.splitlines():
        p = split_terse(line)
        if len(p) < 8:
            continue
        inuse, bssid, ssid, chan, freq, rate, sig, sec = p[:8]
        num = lambda s: int(float(re.search(r"[\d.]+", s).group())) if re.search(r"[\d.]+", s) else 0
        nets.append(make_net(bssid, ssid, num(chan), num(freq), num(rate), False,
                             num(sig), "Open" if sec in ("", "--") else sec, inuse.strip() == "*"))
    return nets


def wifi_iface():
    m = re.search(r"Interface (\S+)", run(["iw", "dev"]))
    return m.group(1) if m else None


def scan_iw():
    iface = wifi_iface()
    if not iface:
        return []
    out = run(["iw", "dev", iface, "scan"])
    nets = []
    for b in re.split(r"(?m)^BSS ", out)[1:]:
        bssid = b[:17]
        freq = re.search(r"freq: (\d+)", b)
        sig = re.search(r"signal: (-?[\d.]+) dBm", b)
        ssid = re.search(r"SSID: (.*)", b)
        if not (freq and sig):
            continue
        rates = [float(r.rstrip("*")) for line in re.findall(r"upported rates: (.*)", b)
                 for r in line.split()]
        rate, est = (int(max(rates)) if rates else 0), False
        if "HE capabilities" in b:
            rate, est = 600, True
        elif "VHT capabilities" in b:
            rate, est = 433, True
        elif "HT capabilities" in b:
            rate, est = 150, True
        if "WPA3" in b or "SAE" in b:
            sec = "WPA3"
        elif "RSN:" in b:
            sec = "WPA2"
        elif "WPA:" in b:
            sec = "WPA"
        elif "Privacy" in b:
            sec = "WEP"
        else:
            sec = "Open"
        f = int(freq.group(1))
        nets.append(make_net(bssid, ssid.group(1) if ssid else "", freq_to_channel(f), f,
                             rate, est, dbm_to_pct(float(sig.group(1))), sec,
                             "associated" in b.split("\n")[0]))
    return nets


RADIO_SPEED = {"802.11b": 11, "802.11a": 54, "802.11g": 54, "802.11n": 300,
               "802.11ac": 866, "802.11ax": 1201, "802.11be": 2882}


def scan_netsh():
    out = run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    nets, ssid, auth, cur = [], "", "", None
    for raw in out.splitlines():
        line = raw.strip()
        m = re.match(r"SSID \d+ : (.*)", line)
        if m:
            ssid, auth, cur = m.group(1).strip(), "", None
            continue
        if line.startswith("Authentication"):
            auth = line.split(":", 1)[1].strip()
            continue
        m = re.match(r"BSSID \d+\s*: (.*)", line)
        if m:
            cur = {"bssid": m.group(1).strip(), "ssid": ssid, "auth": auth,
                   "signal": 0, "radio": "", "chan": 0}
            nets.append(cur)
            continue
        if cur is None or ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        if k == "Signal":
            cur["signal"] = int(v.rstrip("%") or 0)
        elif k == "Radio type":
            cur["radio"] = v
        elif k == "Channel":
            cur["chan"] = int(v or 0)
    res = []
    for n in nets:
        ch = n["chan"]
        res.append(make_net(n["bssid"], n["ssid"], ch, channel_to_freq(ch),
                            RADIO_SPEED.get(n["radio"], 0), True, n["signal"],
                            "Open" if n["auth"].lower() == "open" else n["auth"], False))
    return res


def pick_backend():
    if platform.system() == "Windows":
        return "netsh", scan_netsh
    if shutil.which("nmcli"):
        return "nmcli", scan_nmcli
    if shutil.which("iw"):
        return "iw (root)", scan_iw
    return None, None


# --------------------------------------------------------------------------
# background scanner
# --------------------------------------------------------------------------
class Scanner(threading.Thread):
    def __init__(self, fn, interval):
        super().__init__(daemon=True)
        self.fn, self.interval = fn, interval
        self.nets, self.prev = [], {}
        self.lock = threading.Lock()
        self.kick = threading.Event()
        self.paused = False
        self.scanning = False
        self.last = 0.0
        self.running = True

    def run(self):
        while self.running:
            if not self.paused or self.kick.is_set():
                self.scanning = True
                nets = self.fn()
                with self.lock:
                    self.prev = {n["bssid"]: n["signal"] for n in self.nets}
                    self.nets = nets
                    self.last = time.time()
                self.scanning = False
            self.kick.clear()
            self.kick.wait(self.interval)

    def snapshot(self):
        with self.lock:
            return list(self.nets), dict(self.prev)


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------
SORTS = [("signal", lambda n: n["signal"]), ("essid", lambda n: n["essid"].lower()),
         ("channel", lambda n: n["channel"]), ("speed", lambda n: n["rate"]),
         ("bssid", lambda n: n["bssid"])]
DEFAULT_REVERSE = {"signal": True, "speed": True}


def put(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    try:
        win.addstr(y, x, text[: max(0, w - x - (1 if y == h - 1 else 0))], attr)
    except curses.error:
        pass


def sig_color(p):
    return curses.color_pair(1 if p >= 70 else 2 if p >= 40 else 3)


def draw(stdscr, sc, backend, st):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    nets, prev = sc.snapshot()
    name, rev = SORTS[st["sort"]][0], st["rev"]
    nets.sort(key=SORTS[st["sort"]][1], reverse=rev)

    # title bar
    ago = f"{int(time.time() - sc.last)}s ago" if sc.last else "never"
    state = "SCANNING" if sc.scanning else ("PAUSED" if sc.paused else "LIVE")
    title = f" {APP} v{VERSION} "
    info = f" {backend} | {len(nets)} networks | every {sc.interval}s | last {ago} | {state} "
    put(stdscr, 0, 0, (title + info).ljust(w), curses.color_pair(4) | curses.A_BOLD)

    # column layout
    c_bssid, c_ch, c_band, c_spd, c_sig, c_sec = 17, 4, 5, 11, 15, 12
    fixed = c_bssid + c_ch + c_band + c_spd + c_sig + c_sec + 7 + 2
    c_essid = max(10, w - fixed)
    arrow = "▼" if rev else "▲"

    def hdr(label, key, width):
        return (label + (arrow if key == name else "")).ljust(width)

    header = (" " + hdr("ESSID", "essid", c_essid) + " " + hdr("BSSID", "bssid", c_bssid) + " " +
              hdr("CH", "channel", c_ch) + " " + "BAND".ljust(c_band) + " " +
              hdr("SPEED", "speed", c_spd) + " " + hdr("SIGNAL", "signal", c_sig) + " " +
              "SECURITY".ljust(c_sec))
    put(stdscr, 1, 0, header.ljust(w), curses.color_pair(5) | curses.A_BOLD)

    # layout heights
    panel_h = 6 if h >= 26 else 0
    table_h = max(1, h - 2 - 1 - panel_h)
    st["scroll"] = max(0, min(st["scroll"], max(0, len(nets) - table_h)))

    if not nets:
        msg = "Scanning..." if sc.scanning or not sc.last else \
            "No networks found (is WiFi on? for 'iw' backend run as root)"
        put(stdscr, 3, 2, msg, curses.A_DIM)

    for i, n in enumerate(nets[st["scroll"]: st["scroll"] + table_h]):
        y = 2 + i
        a = curses.color_pair(6) | curses.A_BOLD if n["active"] else 0
        spd = (("~" if n["est"] else "") + f"{n['rate']} Mbps") if n["rate"] else "?"
        mark = "●" if n["active"] else " "
        x = 0
        put(stdscr, y, x, mark + n["essid"][:c_essid].ljust(c_essid), a)
        x += 1 + c_essid + 1
        put(stdscr, y, x, n["bssid"].ljust(c_bssid), a)
        x += c_bssid + 1
        put(stdscr, y, x, str(n["channel"]).ljust(c_ch), a)
        x += c_ch + 1
        put(stdscr, y, x, n["band"].ljust(c_band), a)
        x += c_band + 1
        put(stdscr, y, x, spd.ljust(c_spd), a)
        x += c_spd + 1
        bars = int(n["signal"] / 100 * 8 + 0.5)
        put(stdscr, y, x, "█" * bars + "░" * (8 - bars), sig_color(n["signal"]))
        old = prev.get(n["bssid"])
        tr = " " if old is None or old == n["signal"] else ("↑" if n["signal"] > old else "↓")
        put(stdscr, y, x + 9, f"{n['dbm']:>4}dBm{tr}", sig_color(n["signal"]))
        x += c_sig + 1
        sec = n["security"]
        put(stdscr, y, x, sec[:c_sec].ljust(c_sec),
            curses.color_pair(3 if sec == "Open" else 0))

    # channel congestion panel
    if panel_h:
        top = h - 1 - panel_h
        put(stdscr, top, 0, (" Channel usage ").ljust(w), curses.color_pair(5) | curses.A_BOLD)
        usage = {}
        for n in nets:
            key = (n["band"], n["channel"])
            usage.setdefault(key, []).append(n["signal"])
        cells = []
        for (band, ch), sigs in sorted(usage.items()):
            cnt = len(sigs)
            cells.append((f"{band:>4} ch{ch:<3}", "█" * min(cnt, 10), f" {cnt}", max(sigs)))
        cell_w = 28
        per_row = max(1, w // cell_w)
        for i, (lab, bar, cnt, best) in enumerate(cells[: per_row * (panel_h - 1)]):
            y, x = top + 1 + i // per_row, (i % per_row) * cell_w + 1
            put(stdscr, y, x, lab)
            put(stdscr, y, x + 10, bar.ljust(10), sig_color(best))
            put(stdscr, y, x + 21, cnt)

    # footer
    foot = " q quit  s sort  v reverse  r rescan  +/- interval  space pause  ↑↓ scroll "
    put(stdscr, h - 1, 0, foot.ljust(w), curses.color_pair(4))
    stdscr.refresh()


def tui(stdscr, backend, fn, interval):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)
    curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(5, curses.COLOR_CYAN, -1)
    curses.init_pair(6, curses.COLOR_MAGENTA, -1)
    stdscr.timeout(200)

    sc = Scanner(fn, interval)
    sc.start()
    st = {"sort": 0, "rev": True, "scroll": 0}
    while True:
        draw(stdscr, sc, backend, st)
        k = stdscr.getch()
        h = stdscr.getmaxyx()[0]
        if k in (ord("q"), ord("Q"), 27):
            break
        elif k in (ord("s"), ord("S")):
            st["sort"] = (st["sort"] + 1) % len(SORTS)
            st["rev"] = DEFAULT_REVERSE.get(SORTS[st["sort"]][0], False)
        elif k in (ord("v"), ord("V")):
            st["rev"] = not st["rev"]
        elif k in (ord("r"), ord("R")):
            sc.kick.set()
        elif k == ord(" "):
            sc.paused = not sc.paused
        elif k in (ord("+"), ord("=")):
            sc.interval = min(120, sc.interval + 1)
        elif k in (ord("-"), ord("_")):
            sc.interval = max(1, sc.interval - 1)
        elif k == curses.KEY_UP:
            st["scroll"] -= 1
        elif k == curses.KEY_DOWN:
            st["scroll"] += 1
        elif k == curses.KEY_PPAGE:
            st["scroll"] -= h // 2
        elif k == curses.KEY_NPAGE:
            st["scroll"] += h // 2
    sc.running = False
    sc.kick.set()


def print_once(fn):
    nets = sorted(fn(), key=lambda n: -n["signal"])
    print(f"{'ESSID':<28} {'BSSID':<17} {'CH':>3} {'BAND':<4} {'SPEED':>10} {'SIGNAL':>7}  SECURITY")
    for n in nets:
        spd = (("~" if n["est"] else "") + f"{n['rate']} Mbps") if n["rate"] else "?"
        print(f"{n['essid'][:28]:<28} {n['bssid']:<17} {n['channel']:>3} {n['band']:<4} "
              f"{spd:>10} {n['dbm']:>4}dBm  {n['security']}")


def main():
    ap = argparse.ArgumentParser(description=f"{APP} - btop-style WiFi scanner")
    ap.add_argument("-i", "--interval", type=int, default=3, help="scan interval in seconds")
    ap.add_argument("--once", action="store_true", help="scan once and print a plain table")
    args = ap.parse_args()

    backend, fn = pick_backend()
    if not fn:
        sys.exit("No scan backend found. Install NetworkManager (nmcli) or 'iw' (run as root).")
    if args.once:
        return print_once(fn)
    locale.setlocale(locale.LC_ALL, "")
    try:
        curses.wrapper(tui, backend, fn, max(1, args.interval))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
