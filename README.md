A[README.md](https://github.com/user-attachments/files/33033872/README.md)
# 📡 Wifi_Scanner

A **btop-style live WiFi scanner for the terminal**. See every nearby network at a glance: ESSID, BSSID, channel, band, speed, signal strength and security, plus a channel congestion panel.

- Live, auto-refreshing table with colored signal bars
- Signal trend arrows (↑ / ↓) between scans
- Your connected network is highlighted
- Channel usage panel to find the least crowded channel
- Sort by signal, ESSID, channel, speed or BSSID
- Single file, no external Python dependencies

## 📥 Download

No git needed. Just download the file:

**Option 1: From the browser**
1. Open [`Wifi_Scanner.py`](https://github.com/674Neofo/Wifi_Scanner/blob/main/Wifi_Scanner.py) on this page.
2. Click the **Download raw file** icon (top right of the code).
3. The file is saved to your `Downloads` folder.

**Option 2: From the terminal**
```bash
wget https://raw.githubusercontent.com/674Neofo/Wifi_Scanner/main/Wifi_Scanner.py
```
or, if you don't have `wget`:
```bash
curl -O https://raw.githubusercontent.com/674Neofo/Wifi_Scanner/main/Wifi_Scanner.py
```

**Option 3: Download everything as ZIP**
Click **Code → Download ZIP** at the top of this page, then unzip it.

## ▶️ Run

```bash
cd ~/Downloads
python3 Wifi_Scanner.py
```

### Options

```bash
python3 Wifi_Scanner.py -i 5     # scan every 5 seconds (default: 3)
python3 Wifi_Scanner.py --once   # scan once and print a plain table
```

### Install system-wide (optional)

```bash
sudo cp Wifi_Scanner.py /usr/local/bin/wifi_scanner
wifi_scanner
```

## 📋 Requirements

- Python 3.7+
- **Linux:** NetworkManager (`nmcli`), no root needed. Fallback: `iw` (run with `sudo`)
- **Windows:** `pip install windows-curses` (uses `netsh`)
- macOS is not supported

Install a backend if you see "No scan backend found":

```bash
sudo apt install network-manager     # Debian / Ubuntu
sudo pacman -S networkmanager        # Arch
sudo dnf install NetworkManager      # Fedora
```

## ⌨️ Keys

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit |
| `s` | Cycle sort column |
| `v` | Reverse sort order |
| `r` | Rescan now |
| `+` / `-` | Change scan interval |
| `Space` | Pause / resume |
| `↑` `↓` `PgUp` `PgDn` | Scroll |

## 📝 Notes

- With `nmcli`, speed is the real rate reported by the driver. With `iw` or `netsh`, speed is an estimate based on the WiFi standard and is shown with a `~`.
- Make your terminal at least 26 rows tall to see the channel usage panel.

## 📄 License

MIT
