# Trust, but Verify

> *"довеpяй, но провеpяй"*

**Building a Software Safety Snapshot Before Deploying to Your Fleet**

[MacAD.UK](https://macad.uk) 2026 — Ben Toms & Paul Cossey

---

## About

This repository contains the resources for the MacAD.UK 2026 talk *"Trust, but Verify"*. The session walks through building an automated verification workflow for macOS software titles before deploying them to your fleet.

---

## Links & Resources

### Security Scanning

| Tool | Description | Link |
|------|-------------|------|
| **VirusTotal** | 70+ AV engine scanning of installer media, URLs, and IPs | [virustotal.com](https://www.virustotal.com) |
| **Jamf Threat Labs Binary Scanning** | Mach-O binary deep-scan with YARA rules and AI threat classification | *Beta — speak to Ben or Paul for access* |
| **XProtect** | Apple's built-in YARA-based malware detection | [Apple Security Guide](https://support.apple.com/en-gb/guide/security/sec469d47bd8/web) |

### Objective-See Tools

| Tool | Description | Link |
|------|-------------|------|
| **KnockKnock** | Persistence mechanism baseline scanning | [objective-see.org/products/knockknock.html](https://objective-see.org/products/knockknock.html) |
| **BlockBlock** | Real-time persistence monitoring | [objective-see.org/products/blockblock.html](https://objective-see.org/products/blockblock.html) |
| **LuLu** | macOS firewall / outbound network monitoring | [objective-see.org/products/lulu.html](https://objective-see.org/products/lulu.html) |
| **RansomWhere?** | Ransomware detection via encrypted file creation monitoring | [objective-see.org/products/ransomwhere.html](https://objective-see.org/products/ransomwhere.html) |
| **OverSight** | Camera & microphone access monitoring | [objective-see.org/products/oversight.html](https://objective-see.org/products/oversight.html) |
| **ReiKey** | Keyboard event tap (keylogger) detection | [objective-see.org/products/reikey.html](https://objective-see.org/products/reikey.html) |
| **Dylib Hijack Scanner (DHS)** | Dynamic library hijack detection | [objective-see.org/products/dhs.html](https://objective-see.org/products/dhs.html) |

### Threat Intelligence & Blog Posts

| Topic | Link |
|-------|------|
| LockBit macOS Ransomware (2023) | [objective-see.org/blog/blog_0x75.html](https://objective-see.org/blog/blog_0x75.html) |
| Turtle Ransomware | [objective-see.org/blog/blog_0x76.html](https://objective-see.org/blog/blog_0x76.html) |
| OSX.Dummy (2018) | [objective-see.org/blog/blog_0x32.html](https://objective-see.org/blog/blog_0x32.html) |
| OSX.FruitFly — Keylogger undetected 13+ years | [objective-see.org/blog/blog_0x36.html](https://objective-see.org/blog/blog_0x36.html) |
| Zoom Dylib Hijack Vulnerability (2020) | [objective-see.org/blog/blog_0x56.html](https://objective-see.org/blog/blog_0x56.html) |
| HandBrake Trojanised Mirror (2017) | [objective-see.org/blog/blog_0x1D.html](https://objective-see.org/blog/blog_0x1D.html) |
| XcodeGhost (2015) | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/novel-malware-xcodeghost-modifies-xcode-infects-apple-ios-apps) |
| KeRanger Ransomware (2016) | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/new-os-x-ransomware-keranger-infected-transmission-bittorrent-client-installer) |
| Codecov Supply Chain Attack (2021) | [about.codecov.io/security-update](https://about.codecov.io/security-update) |
| XProtect Weekly Updates | [eclecticlight.co](https://eclecticlight.co/2025/07/11/what-happened-to-xprotect-this-week) |

### Other Tools & Platforms

| Tool | Description | Link |
|------|-------------|------|
| **Munki** | Open-source macOS software management | [github.com/munki/munki](https://github.com/munki/munki) |
| **AutoPkg** | Automated macOS software packaging | [github.com/autopkg/autopkg](https://github.com/autopkg/autopkg) |
| **pkgcheck** | macOS installer package analysis and validation | [github.com/scriptingosx/pkgcheck](https://github.com/scriptingosx/pkgcheck) |
| **VirusTotalReporter** | AutoPkg processor for VirusTotal scanning of downloads | [github.com/autopkg/nstrauss-recipes](https://github.com/autopkg/nstrauss-recipes/tree/master/VirusTotalReporter) |
| **Jamf Auto Update** | Automated app packaging and deployment | [datajar.co.uk/products/jamf-auto-update](https://datajar.co.uk/products/jamf-auto-update) |
| **Objective-See** | Free macOS security tools by Patrick Wardle | [objective-see.org](https://objective-see.org) |
