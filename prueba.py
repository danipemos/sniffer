import configparser
import easywebdav
import ftplib
import paramiko
from scp import SCPClient
import boto3
from requests.auth import HTTPDigestAuth,HTTPBasicAuth


auth_method={"BASIC": HTTPBasicAuth,
             "DIGEST": HTTPDigestAuth}

config=configparser.ConfigParser()
config.read('general.ini')
def webdav(file):
    url="server.com"
    user="prueba"
    password="prueba"
    remote_path="webdav"
    puerto="40"
    auth="BASIC"
    webdav= easywebdav.connect(
        host=url,
        path=remote_path,
        protocol="http",
        auth=auth_method.get(auth)(username=user,password=password)
    )
    webdav.session.verify=False
    webdav.upload(file,file)
    
webdav("capture_20250324_144621.pcap")
"""
def ftp(file):
        host="192.168.65.128"
        username="user_ftp"
        password="2003"
        remote_path="/home/user_ftp"
        with ftplib.FTP(host, username, password) as ftp:
            ftp.cwd(remote_path)
            with open(file, 'rb') as f:
                ftp.storbinary(f'STOR {file}', f)

ftp("capture_20250320_142520.pcap")

"""
"""
def scp(file):
        host="192.168.65.128"
        username="user_ftp"
        password="2003"
        remote_path="/home/user_ftp"
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
        ssh.connect(host, username=username, password=password)
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(file, remote_path)

scp("capture_20250320_142521.pcap")
"""
""""""
def sftp(file):
        host="192.168.65.128"
        username="user_ftp"
        password="2003"
        remote_path="/home/user_ftp"
        if not remote_path.endswith('/'):
            remote_path += '/'
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.load_system_host_keys()
        client.connect(host, username=username, password=password)
        sftp_client = client.open_sftp()
        sftp_client.put(file, remote_path+file)

def s3(file):
        access_key="AKIAQ75ITECAH36LZRVP"
        secret_key="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"
        bucket_name="tfg-sniffer"
        s3 = boto3.resource('s3',aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        s3.Bucket(bucket_name).upload_file(file, file)

#s3("capture_20250320_142522.pcap")
