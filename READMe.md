
# MiniWireshark

**A lightweight network packet analyzer inspired by Wireshark, built from scratch in C# with Avalonia UI and SharpPcap.**

MiniWireshark is a personal software development project aiming to recreate some of Wireshark's core capabilities in a modern, cross-platform desktop application.

The application captures live network traffic, dissects network protocols, reconstructs TCP streams, analyzes encrypted traffic when session keys are available, and provides tools for inspecting network activity.

> **Project status:** Active development. Core packet capture, protocol dissection, display filters, TCP stream reconstruction, live statistics, and several advanced analysis features have been implemented. Some features are still being integrated into the application.

---

## Features

### Live Packet Capture
- Capture packets from available network interfaces.
- Monitor live Ethernet traffic.
- Display captured packets in a structured packet list.
- Inspect individual packets and their decoded fields.

### Protocol Dissection
Implemented protocol dissectors include:

- **Ethernet** — MAC addresses and frame information.
- **IPv4** — IP addresses and packet headers.
- **IPv6** — IPv6 addressing and headers.
- **TCP** — Ports, flags, sequence numbers, and connection information.
- **UDP** — Datagram and port information.
- **ICMP** — Control and diagnostic messages.
- **ARP** — IPv4-to-MAC address resolution.
- **DNS** — Domain name queries and responses.

### Packet Inspection and Visualization
- Color-coded packets based on their protocols.
- Structured protocol details displayed in a tree.
- Hexadecimal packet inspection.
- Readable representations of decoded protocol fields.

### Display Filters
Filter captured traffic using expressions such as:

```text
tcp
udp
dns
icmp
tcp.port == 443
ip.addr == 192.168.1.10
```

*The examples illustrate the intended filter syntax; supported expressions depend on the current filter implementation.*

### TCP Stream Reconstruction
- Reconstruct TCP conversations from captured packets.
- Inspect stream contents in readable text or hexadecimal format.
- View TLS-related stream information.
- Identify TCP retransmissions in packet analysis.

### TLS Analysis
- TLS session decryption using keys supplied through `SSLKEYLOGFILE`.
- Support for analyzing decrypted TLS traffic when compatible session keys are available.
- TLS stream inspection and protocol analysis.

TLS decryption depends on the availability of valid session keys. It does not break encryption or independently recover missing keys.

### HTTP Analysis
- HTTP/1.1 message parsing.
- Support for chunked transfer encoding.
- Support for gzip-compressed HTTP content.
- HTTP/2 frame decoding.
- HPACK header decompression.

HTTP/2 and HTTP/1.1 capabilities have been implemented and tested in the Core layer, with application integration in progress.

### Live Statistics
- Live traffic statistics in a dedicated window.
- Protocol distribution.
- Top talkers and traffic overview.

### TCP Anomaly Detection
The analysis engine includes detection capabilities for events such as:

- TCP resets (RST).
- SYN packets without an observed response.
- Suspiciously low IP TTL values.
- TCP retransmissions.

These indicators are intended to help investigate unusual traffic. They are not, by themselves, proof of malicious activity.

### Application-Aware Traffic Analysis
- Associate TCP connections with local processes using process IDs.
- Display the associated process name.
- Filter traffic by process name or process ID.
- Select an application to investigate its network connections.

On Windows, process association uses the operating system's TCP connection table. This approach may miss short-lived connections or traffic that cannot be reliably associated with a TCP socket.

---

## Tech Stack

| Technology | Purpose |
|---|---|
| C# | Main programming language |
| .NET | Application runtime and development platform |
| Avalonia UI | Cross-platform desktop interface |
| SharpPcap | Network packet capture |
| Custom protocol dissectors | Packet parsing and protocol analysis |
| Windows TCP connection APIs | Process-aware TCP connection identification |

---

## Architecture

The project separates packet analysis from the graphical interface.

```text
MiniWireshark
├── MiniWireshark.Core
│   ├── Packet Capture
│   ├── Protocol Dissection
│   ├── TCP Stream Reconstruction
│   ├── TLS / HTTP Analysis
│   ├── Statistics
│   └── Anomaly Detection
│
└── MiniWireshark.Gui
    ├── Avalonia UI
    ├── Packet List
    ├── Packet Details
    ├── Display Filters
    ├── TCP Stream Viewer
    └── Statistics Window
```

*This diagram describes the logical separation of responsibilities. Actual project directories and class names may differ.*

---

## Roadmap

### In Progress
- [ ] Complete integration of application-aware traffic analysis.
- [ ] Improve and validate live protocol statistics.
- [ ] Refine TCP retransmission and anomaly indicators.

### Planned
- [ ] TLS Server Name Indication (SNI) extraction.
- [ ] Packet search and navigation.
- [ ] Export reconstructed TCP streams.
- [ ] PCAP file import.
- [ ] PCAP file export.
- [ ] Improve anomaly detection and analysis reporting.
- [ ] Evaluate ETW-based monitoring for short-lived application connections.

---

## Security and Privacy

MiniWireshark is intended for educational purposes, network troubleshooting, and authorized traffic analysis.

- Only capture traffic on networks and interfaces you are authorized to monitor.
- TLS decryption requires compatible session keys obtained legitimately.
- Captured packets may contain sensitive information, including credentials, personal data, and internal network details.
- Handle packet captures and exported files securely.

---

## Current Status

MiniWireshark is an evolving personal project focused on understanding network protocols, packet capture, TCP/IP internals, and desktop application development.

The goal is to progressively build a capable packet analyzer while keeping the protocol analysis engine modular and extensible.

---

## Author

**Aztek71**

Full-Stack Developer · Software Developer · Tech Enthusiast

GitHub: [@Aztek71](https://github.com/Aztek71)

---

*Built with C# and curiosity about how networks work.*
