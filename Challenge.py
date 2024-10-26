# app.py
from scapy.all import sniff, AsyncSniffer, conf
from collections import Counter
import argparse

# Variables globales para almacenar estadísticas
total_packets = 0
protocol_counter = Counter()
src_ip_counter = Counter()
dst_ip_counter = Counter()

def process_packet(packet):
    global total_packets
    total_packets += 1

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        proto = packet["IP"].proto
        pkt_size = len(packet)

        protocol_counter[proto] += 1
        src_ip_counter[src_ip] += pkt_size
        dst_ip_counter[dst_ip] += pkt_size

def print_statistics():
    print(f"\n--- Resumen del tráfico ---")
    print(f"Total de paquetes capturados: {total_packets}")
    print("Número de paquetes por protocolo:")
    for proto, count in protocol_counter.items():
        print(f"  - Protocolo {proto}: {count} paquetes")

    print("\nTop 5 IPs de origen con más tráfico:")
    for ip, count in src_ip_counter.most_common(5):
        print(f"  - {ip}: {count} bytes")

    print("\nTop 5 IPs de destino con más tráfico:")
    for ip, count in dst_ip_counter.most_common(5):
        print(f"  - {ip}: {count} bytes")

def main():
   print("Escribe 'start <interfaz>' para comenzar la captura o 'stop' para detenerla. \n Interfaces disponibles: 'Ethernet' o 'Wi-Fi'")
   sniffer = None  # Variable para almacenar el sniffer

   while True:
        command = input("Ingresa comando: ")

        if command.startswith("start "):
            if sniffer and sniffer.running:
                print("La captura ya está en curso.")
            else:
                interface = command.split(" ")[1]  # Obtener la interfaz del comando
                print(f"Capturando paquetes en la interfaz {interface}...")
                sniffer = AsyncSniffer(iface=interface, prn=process_packet, store=False, socket=conf.L3socket)
                sniffer.start()

        elif command == "stop":
            if sniffer and sniffer.running:
                sniffer.stop()
                print("Captura detenida.")
                print_statistics()  # Mostramos las estadísticas
            else:
                print("No se ha iniciado ninguna captura.")

        else:
            print("Comando no reconocido. Usa 'start <interfaz>' para comenzar y 'stop' para detener.")

if __name__ == "__main__":
    main()
