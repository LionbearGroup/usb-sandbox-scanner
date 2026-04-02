# USB Sandbox Scanner

Kernel-level USB malware scanner for Linux. Automatically scans any USB drive on insertion using **ClamAV** inside an isolated **Linux namespace** (read-only, noexec, nosuid, nodev). Optional **VirusTotal** multi-engine analysis.

## How it works

```
USB inserted → udev detects → systemd starts sandboxed scan → desktop notification + HTML report
```

1. **udev rule** detects USB block devices and delegates to systemd (no 5s timeout issue)
2. **udisks2 auto-mount is blocked** (`UDISKS_AUTO=0`) so the scanner gets the raw device
3. The scan script **mounts read-only** inside a new mount namespace (`unshare --mount`)
4. **ClamAV** recursively scans all files (archives, PDFs, OLE2, HTML, mail)
5. If configured, suspicious files are submitted to **VirusTotal** for multi-engine analysis
6. An **HTML report** is generated and a **desktop notification** is sent
7. The device is **unmounted** automatically on exit (even on error)

## Security layers

| Layer | Protection |
|-------|------------|
| Mount namespace (`unshare`) | Filesystem changes can't leak to host |
| `ro,noexec,nosuid,nodev` | No execution, no privilege escalation, no device files |
| systemd hardening | `ProtectSystem=strict`, `PrivateTmp`, `MemoryMax=512M`, seccomp filters |
| ClamAV | 3.6M+ malware signatures, updated automatically via `freshclam` |
| VirusTotal (optional) | 70+ antivirus engines for second-opinion scanning |

## Files

| File | Description |
|------|-------------|
| `install.sh` | Installer — installs dependencies, copies files, configures system |
| `usb-sandbox-scan.sh` | Main scan script — namespace isolation + ClamAV + VirusTotal + HTML report |
| `99-usb-sandbox.rules` | udev rule — triggers systemd service on USB insertion |
| `usb-sandbox@.service` | systemd template service — runs scan with security hardening |

## Installation

```bash
git clone https://github.com/JPVLakes/usb-sandbox-scanner.git
cd usb-sandbox-scanner
chmod +x install.sh usb-sandbox-scan.sh
sudo ./install.sh
```

The installer will:
- Install ClamAV and dependencies
- Update virus signature database
- Copy scripts and config to system directories
- Optionally configure VirusTotal API key

## VirusTotal (optional)

Get a free API key at [virustotal.com](https://www.virustotal.com) and either:
- Enter it during `install.sh` when prompted, or
- Configure it manually:

```bash
echo 'VIRUSTOTAL_API_KEY=your_key_here' | sudo tee /etc/usb-sandbox.env
sudo chmod 600 /etc/usb-sandbox.env
```

## Usage

### Automatic (plug and play)

Just insert a USB drive. The scan starts automatically.

### Manual scan

```bash
sudo usb-sandbox-scan.sh sdb1
```

### View logs

```bash
journalctl -fu 'usb-sandbox@*'
```

### Reports

HTML reports are saved to `/var/log/usb-sandbox/reports/`.

## Requirements

- Linux with systemd and udev
- ClamAV (`clamav`, `clamav-daemon`, `clamav-freshclam`)
- `util-linux` (for `unshare`)
- `libnotify-bin` (for desktop notifications)
- `curl` (for VirusTotal, optional)

## License

MIT
