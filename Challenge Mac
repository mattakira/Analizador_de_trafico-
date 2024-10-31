from scapy.all import sniff, AsyncSniffer  
from collections import Counter
import argparse
import mysql.connector
import os

# Variables globales para almacenar estadísticas
total_paquetes = 0
contador_protocolo = Counter()
contador_ip_origen = Counter()
contador_ip_destino = Counter()

# Conexión a la base de datos
def connect_db():
    try:
        connection = mysql.connector.connect(
            host="127.0.0.1",       # IP localhost base de datos
            user="root",
            password="adminroot",
            database="TrafficAnalysis",       # Nombre de la base de datos 
            port=3306               # Puerto 
        )
        print("Conexión exitosa a la base de datos.")
        return connection
    except mysql.connector.Error as err:
        print(f"Error de conexión a la base de datos: {err}")
        return None

# Guardar estadísticas en la base de datos:
def guardar_en_db():
    print("connect en db...")
    db_connection = connect_db()
    print("conectado en db...")
    if db_connection is None:
        print("Error: no se pudo establecer conexión con la base de datos.")
        return
    
    cursor = db_connection.cursor()

    # Insertar en estadisticas_paquetes
    cursor.execute("INSERT INTO estadisticas_paquetes (total_paquetes) VALUES (%s)", (total_paquetes,))
    id_estadisticas_paquetes = cursor.lastrowid
    print(f"ID de estadisticas_paquetes insertado: {id_estadisticas_paquetes}")

    # Insertar en estadisticas_protocolos
    for protocolo, count in contador_protocolo.items():
        cursor.execute("INSERT INTO estadisticas_protocolos (id_estadisticas_paquetes, protocolo, cantidad_paquetes) VALUES (%s, %s, %s)", 
                       (id_estadisticas_paquetes, protocolo, count))
        print(f"Insertado en estadisticas_protocolos - Protocolo: {protocolo}, Cantidad: {count}")

    # Insertar en trafico_ip para IPs de origen
    for ip, total_bytes in contador_ip_origen.items():
        cursor.execute("INSERT INTO trafico_ip (id_estadisticas_paquetes, direccion_ip, direccion, total_bytes) VALUES (%s, %s, 'origen', %s)", 
                       (id_estadisticas_paquetes, ip, total_bytes))
        print(f"Insertado en trafico_ip - IP de origen: {ip}, Bytes: {total_bytes}")

    # Insertar en trafico_ip para IPs de destino
    for ip, total_bytes in contador_ip_destino.items():
        cursor.execute("INSERT INTO trafico_ip (id_estadisticas_paquetes, direccion_ip, direccion, total_bytes) VALUES (%s, %s, 'destino', %s)", 
                       (id_estadisticas_paquetes, ip, total_bytes))
        print(f"Insertado en trafico_ip - IP de destino: {ip}, Bytes: {total_bytes}")

    # Confirmar cambios y cerrar conexión
    db_connection.commit()
    cursor.close()
    db_connection.close()
    print("Estadísticas guardadas en la base de datos.")

def process_packet(packet):
    global total_paquetes
    total_paquetes += 1

    if packet.haslayer("IP"):
        ip_origen = packet["IP"].src
        ip_destino = packet["IP"].dst
        protocolo = packet["IP"].proto
        long_paquete = len(packet)

        contador_protocolo[protocolo] += 1
        contador_ip_origen[ip_origen] += long_paquete
        contador_ip_destino[ip_destino] += long_paquete

def print_statistics():
    print(f"\n--- Resumen del tráfico ---")
    print(f"Total de paquetes capturados: {total_paquetes}")
    print("Número de paquetes por protocolo:")
    for protocolo, count in contador_protocolo.items():
        print(f"  - Protocolo {protocolo}: {count} paquetes")

    print("\nTop 5 IPs de origen con más tráfico:")
    for ip, count in contador_ip_origen.most_common(5):
        print(f"  - {ip}: {count} bytes")

    print("\nTop 5 IPs de destino con más tráfico:")
    for ip, count in contador_ip_destino.most_common(5):
        print(f"  - {ip}: {count} bytes")

    # Guardar las estadísticas en la base de datos
    print("Guardando en db...")
    guardar_en_db()
    print("Finalizando db")

def main(interface):
    print(f"Escribe 'start' para comenzar la captura y 'stop' para detenerla.")
    
    while True:
        command = input("Ingresa comando (start/stop): ").strip().lower()

        if command == "start":
            print(f"Capturando paquetes en la interfaz {interface}...")

            # Usamos AsyncSniffer para que la captura sea asíncrona
            sniffer = AsyncSniffer(iface=interface, prn=process_packet, store=False)
            sniffer.start()

        elif command == "stop":
            if 'sniffer' in locals():
                sniffer.stop()  # Detenemos la captura de paquetes
                print("Captura detenida.")
                print_statistics()  # Mostramos las estadísticas y guardamos en la BD
            else:
                print("No se ha iniciado ninguna captura.")
            break
        else:
            print("Comando no reconocido. Usa 'start' para comenzar y 'stop' para detener.")

if _name_ == "_main_":
    parser = argparse.ArgumentParser(description="Aplicación de análisis de tráfico de red")
    parser.add_argument("interface", help="Interfaz de red a usar para la captura")
    args = parser.parse_args()

    # Verificar si se está ejecutando con permisos de root en macOS
    if os.geteuid() != 0:
        print("Este script necesita permisos de administrador. Ejecútalo con 'sudo'.")
    else:
        main(args.interface)  # Llamada completa a la función main
