#!/bin/bash
# Actualización del sistema
apt update && apt upgrade -y
# Instalación de dependencias
apt install -y zabbix-agent2
apt install -y python3-scapy python3-pcapy python3-paramiko python3-requests python3-scp python3-easywebdav python3-boto3 python3-gnupg gcc libpcap-dev
# Instalación de paquetes adicionales
wget https://http.kali.org/pool/main/p/python-pyzipper/python3-pyzipper_0.3.6-5_all.deb
dpkg -i python3-pyzipper_0.3.6-5_all.deb || apt-get install -f -y
rm python3-pyzipper_0.3.6-5_all.deb
wget https://repo.zabbix.com/zabbix-tools/debian-ubuntu/pool/main/p/python3-zabbix-utils/python3-zabbix-utils_2.0.2-1_all.deb
dpkg -i python3-zabbix-utils_2.0.2-1_all.deb || apt-get install -f -y
rm python3-zabbix-utils_2.0.2-1_all.deb
gcc -shared -o liba.so -fPIC sniffer/main.c -lpcap
useradd -m -s /bin/bash sniffer
echo "sniffer ALL=(ALL) NOPASSWD: /usr/bin/systemctl is-active sniffer.service, /usr/bin/systemctl start sniffer.service, /usr/bin/systemctl stop sniffer.service, /usr/bin/wg-quick up /home/sniffer/wg0.conf, /usr/bin/wg-quick down /home/sniffer/wg0.conf" | tee -a /etc/sudoers.d/010_pi-nopasswd
SNIFFER_PASS=$(openssl rand -base64 16)
echo "sniffer:$SNIFFER_PASS" | chpasswd
mkdir -p /opt/sniffer/
cp sniffer/*.py /opt/sniffer/
chown -R sniffer:sniffer /opt/sniffer/
chmod 750 /opt/sniffer/
chmod 750 /opt/sniffer/*.py
cp sniffer/config.ini /home/sniffer/
cp liba.so /usr/lib/
chmod 644 /usr/lib/liba.so
mkdir /home/sniffer/captures
mkdir /home/sniffer/.gnupg
chown -R sniffer:sniffer /home/sniffer/
nmcli connection add type bridge con-name br0 ifname br0
nmcli connection add type ethernet con-name br0-slave-eth0 ifname eth0 master br0
nmcli connection add type ethernet con-name br0-slave-eth1 ifname eth1 master br0
nmcli connection up br0
nmcli connection up br0-slave-eth0
nmcli connection up br0-slave-eth1
nmcli connection modify br0 ipv4.method disable
nmcli connection modify br0 ipv6.method disable
# Crear el archivo de servicio systemd
cat > /lib/systemd/system/sniffer.service << EOF
[Unit]
Description=Sniffer
After=network-online.target
[Service]
ExecStartPre=/bin/bash -c 'while true; do \
  ip link show eth0 | grep -q "state UP" && \
  ip link show eth1 | grep -q "state UP" && break; \
  echo "Waiting for eth0 and eth1 to be up..."; \
  sleep 1; \
done'
ExecStart=/bin/python /opt/sniffer/sniffer.py
WorkingDirectory=/home/sniffer/captures
Restart=always
User=sniffer
Group=sniffer
TimeoutStopSec=infinity
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
[Install]
WantedBy=multi-user.target
EOF
# Habilitar y arrancar el servicio
systemctl disable --now bluetooth.service
systemctl disable --now alsa-restore.service
systemctl disable --now NetworkManager-wait-online.service
systemctl disable --now apt-daily-upgrade.service
systemctl disable --now ModemManager.service
systemctl disable --now rpc-statd-notify.service
systemctl disable --now avahi-daemon.service
systemctl disable --now apt-daily.service
apt install -y wireguard resolvconf python3-netifaces
systemctl restart NetworkManager
systemctl enable --now sniffer.service
echo "Enter the IP of the Zabbix Server in the configuration file (/etc/zabbix/zabbix_agent2.conf). And enable de service"
echo "Password for sniffer user is $SNIFFER_PASS"
