# 🎭 DHCP Rogue Server (Spoofing)

**Course:** Network Security (Seguridad Informática)  
**Student:** Junior (ID: 2024-2015)  
**Framework:** Python 3 + Scapy

## ⚠️ Disclaimer
**Educational use only.** This tool intercepts network traffic. Use only in authorized testing environments.

## 🎥 Video Demonstration
[PASTE YOUR YOUTUBE/DRIVE LINK HERE]

---

## 1. Objective
This script establishes a **Rogue DHCP Server** that competes with the legitimate server. By responding faster to `DHCP DISCOVER` requests, it assigns a malicious network configuration to new clients.
**The Payload:** The attacker (`20.24.20.2`) assigns itself as the **Default Gateway** and **DNS Server**, effectively achieving a **Man-in-the-Middle (MitM)** position to intercept or manipulate traffic.

## 2. Network Topology
* **Subnet:** 20.24.20.0/24
* **Attacker (Rogue Server):** 20.24.20.2
* **Victim:** Windows 10 Client.
* **Malicious Gateway:** 20.24.20.2

![Topology Screenshot](img/topology.png)

## 3. Requirements & Usage

### Installation
```bash
git clone https://github.com/deiviRd18/D31B1-DHCP-Rogue-Server.git
cd D31B1-DHCP-Rogue-Server
pip3 install scapy
```
### Configuration
You can modify the malicious parameters in the script:
```python
FAKE_GATEWAY = "20.24.20.2"
FAKE_DNS = "20.24.20.2"

```
Execution

Disable the legitimate DHCP server (or race against it) and run:
`sudo python3 d31b1_dhcp_rogue_v2.py`

4. Proof of Concept (PoC)
Victim Compromised
The Windows client receives the IP configuration pointing to the attacker.

DORA Process
The script successfully handles the full DHCP handshake (Discover -> Offer -> Request -> Ack).

5. Mitigation Strategies
DHCP Snooping: The primary defense. Switches are configured to trust DHCP OFFER messages only from specific uplink ports connected to legitimate servers.

VLAN Segmentation: Isolate critical infrastructure.
