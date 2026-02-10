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
### Configuration
You can modify the malicious parameters in the script:
```python
FAKE_GATEWAY = "20.24.20.2"
FAKE_DNS = "20.24.20.2"```

```
That is a great idea, Junior! Doing it in English makes your portfolio look much more professional and international, especially for a cybersecurity profile.

Here are the 3 README.md templates in professional technical English. Just copy, paste, and add your screenshots.

📂 Repository 1: DHCP Starvation
Suggested Name: D31B1-DHCP-Starvation

Create a file named README.md and paste this:

Markdown
# 💀 DHCP Starvation Attack Tool

**Course:** Network Security (Seguridad Informática)  
**Student:** Junior (ID: 2024-2015)  
**Framework:** Python 3 + Scapy

## ⚠️ Disclaimer
This tool is for **educational purposes only**. It was developed to demonstrate network vulnerabilities in a controlled laboratory environment. Unauthorized use against systems you do not own is illegal.

## 🎥 Video Demonstration
[PASTE YOUR YOUTUBE/DRIVE LINK HERE]

---

## 1. Objective
The main objective of this script is to perform a **Denial of Service (DoS)** attack against a legitimate DHCP server. The tool generates thousands of DHCP DISCOVER packets using randomized spoofed MAC addresses. This exhausts the server's IP address pool (DHCP Binding Table), preventing legitimate clients from obtaining an IP address and connecting to the network.

## 2. Network Topology & Scenario
* **Network Segment:** 20.24.20.0/24 (Based on Student ID).
* **Victim Server:** Cisco Router (20.24.20.15).
* **Attacker:** Kali Linux (20.24.20.2).
* **Interface:** eth0 (VMnet3 Isolated Network).

![Topology Screenshot](img/topology.png)

## 3. Requirements & Usage
* **OS:** Kali Linux / Debian-based Linux.
* **Dependencies:** Python 3, Scapy.
* **Privileges:** Root access is required to inject raw packets.

### Installation
```bash
git clone [https://github.com/your-username/D31B1-DHCP-Starvation.git](https://github.com/your-username/D31B1-DHCP-Starvation.git)
cd D31B1-DHCP-Starvation
pip3 install scapy
Execution
Bash
sudo python3 d31b1_dhcp_starvation.py
4. Proof of Concept (PoC)
Script Execution
The script flooding the network with fake MAC addresses.

Impact on the Router
The command show ip dhcp binding reveals the IP pool is fully exhausted.

5. Mitigation Strategies
To defend against this attack in enterprise environments:

Port Security: Limit the number of MAC addresses allowed on a single switch port (e.g., max 2 MACs).

DHCP Snooping: Configure the switch to rate-limit DHCP packets and validate that requests come from trusted sources.


---

### 📂 Repository 2: DHCP Rogue Server
**Suggested Name:** `D31B1-DHCP-Rogue-Server`

Create a file named `README.md` and paste this:

```markdown
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
