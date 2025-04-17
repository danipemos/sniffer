from scapy.all import *

# Definir la dirección de origen y destino IPv6
src_ip = "::1"  # Dirección de origen IPv6 (puedes cambiarla según tu red)
dst_ip = "::1"  # Dirección de destino IPv6 (puedes cambiarla según tu red)

# Crear el paquete TCP sobre IPv6
packet = IPv6(src=src_ip, dst=dst_ip)/TCP(dport=80, sport=12345, flags="S")  # Paquete SYN

# Enviar el paquete
while True:
    send(packet)
    time.sleep(1)
