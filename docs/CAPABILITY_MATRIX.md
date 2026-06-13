# ISEC Collector Capability Matrix

This matrix documents what each collector **actually does today**, per operating
system, derived directly from the collector source in `src/collectors/`. It is
deliberately honest: a capability is only marked supported if the code path
exists and targets that OS correctly. Known gaps are called out so reviewers and
operators are never misled, and so the cross-platform hardening work (Pillar 5 of
the product roadmap) has a concrete punch-list.

**Legend**

- ✅ Supported — a correct, OS-appropriate code path exists.
- ⚠️ Partial / known gap — runs, but uses an assumption that is wrong or weak on
  that OS (documented below).
- ❌ Not supported — intentionally returns nothing on that OS.

> Status reflects code review only. None of these have been re-verified on a
> clean machine of each OS yet — that real-machine verification is its own
> roadmap item. Until then, treat ✅ as "implemented", not "certified".

## Summary

| Collector | Windows | Linux | macOS |
|---|:--:|:--:|:--:|
| Browser history — Chrome | ✅ | ✅ | ⚠️ |
| Browser history — Firefox | ✅ | ✅ | ⚠️ |
| Browser history — Edge | ✅ | ❌ | ❌ |
| File metadata | ✅ | ✅ | ⚠️ |
| Network connections | ✅ | ✅ | ⚠️ |
| System logs | ✅ | ✅ | ⚠️ |

## Details & known gaps

### Browser history (`browser_history.py`)

- **Detection** correctly checks Windows, Linux, and macOS install locations for
  Chrome, Firefox, and Edge.
- **Chrome / Firefox on macOS (⚠️):** history *reading* uses the Linux profile
  paths (`~/.config/google-chrome/Default/History`, `~/.mozilla/firefox`). On
  macOS these live under `~/Library/Application Support/...`, so a browser is
  detected but no history is read. *Fix:* add macOS profile paths in
  `_collect_browser_history`.
- **Edge (❌ on Linux/macOS):** intentionally Windows-only (`return []` elsewhere).
  Edge on macOS/Linux uses a Chromium profile and could be supported later.
- All platforms: collection is **consent-gated** (`browser_data` consent) and the
  DB file is copied before reading to avoid lock issues. Good.

### File metadata (`file_metadata.py`)

- **Windows / Linux (✅):** scans OS-appropriate directories with depth/file caps.
- **macOS (⚠️):** the non-Windows scan list uses `/home`, but macOS user homes
  live under `/Users`; `/home` typically doesn't exist, so user-tree coverage is
  reduced (system dirs like `/etc`, `/var/log`, temp still work). *Fix:* add
  `/Users` on macOS.
- **Owner on Windows (⚠️):** returns the placeholder `"SYSTEM"` (real owner
  lookup needs `pywin32`). Unix uses `pwd` correctly. *Fix:* real Windows owner
  resolution.

### Network connections (`network_connections.py`)

- **Windows (✅):** resolves `netstat.exe` from trusted System32/Sysnative paths
  (no PATH hijack) and parses TCP connections.
- **Linux (✅):** uses `netstat -tuln`, falls back to `ss -tuln`, both resolved
  from absolute trusted paths.
- **macOS (⚠️):** BSD `netstat` does not accept the Linux-style `-tuln` flags, and
  `ss` is not present, so collection likely returns empty on macOS. *Fix:* add a
  BSD/macOS code path (e.g. `netstat -an -p tcp` / `lsof -i`).
- Security plus: external tools are only run from absolute, trusted system paths.

### System logs (`system_logs.py`)

- **Windows (✅):** PowerShell `Get-WinEvent -LogName System` (resolved from
  trusted paths), parsed from JSON.
- **Linux (✅):** reads `/var/log/syslog` or `/var/log/messages` (last 50 lines).
- **macOS (⚠️):** reads `/var/log/system.log`, which modern macOS has largely
  replaced with unified logging; this file is often empty/absent. *Fix:* use the
  `log show` command on macOS.

## Cross-cutting notes

- **Privileges:** some sources need elevation (full file trees, the Windows
  Security event channel). Collectors degrade gracefully — they catch errors and
  record an error/skip evidence record rather than crashing. The roadmap adds an
  explicit, machine-readable *skip reason* + capability self-report.
- **Provenance:** every record stores `actor`, `workstation_id`, `ip_address`,
  and a timestamp. The roadmap generalizes this into a structured provenance
  block per the collector plugin interface.
- **Sampling:** collectors store a capped sample (e.g. first 10) plus a count for
  storage efficiency; full-capture is a roadmap option.

## Roadmap punch-list (from the gaps above)

- [ ] macOS browser profile paths (Chrome/Firefox) in `_collect_browser_history`.
- [ ] macOS `/Users` in the file-metadata scan list.
- [ ] macOS/BSD network path (`netstat -an -p tcp` or `lsof -i`).
- [ ] macOS unified-logging path (`log show`) for system logs.
- [ ] Real Windows file-owner resolution (`pywin32`).
- [ ] Edge-on-Chromium support for macOS/Linux (optional).
- [ ] CI matrix (ubuntu/windows/macos) to exercise these paths automatically.

*These macOS fixes are intentionally **documented, not blind-patched** — they
touch OS-specific behavior that must be verified on a real Mac before being
marked ✅.*
