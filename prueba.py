from zabbix_utils import Sender

sender = Sender(
    server='localhost',
    port=10051,
    config_path='/etc/zabbix/zabbix_agent2.conf')

response = sender.send_value('host','sniffer.time','10')

print(response)