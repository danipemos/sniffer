import configparser
import ftplib
import boto3
import easywebdav
import paramiko
from scp import SCPClient
from requests.auth import HTTPDigestAuth,HTTPBasicAuth
import requests
import os
import config_search
auth_method={"Basic": HTTPBasicAuth,
             "Digest": HTTPDigestAuth}


config=configparser.ConfigParser()
config.read(config_search.search_config())

def ftp(file):
    host=config.get('FTP','Server')
    username=config.get('FTP','Username')
    password=config.get('FTP','Password')
    remote_path=config.get('FTP','RemotePath')
    with ftplib.FTP(host, username, password) as ftp:
        ftp.cwd(remote_path)
        with open(file, 'rb') as f:
            ftp.storbinary(f'STOR {file}', f)
    ftp.close()

def s3(file):
        access_key=config.get('S3','AccessKey')
        secret_key=config.get('S3','SecretKey')
        bucket_name=config.get('S3','BucketName')
        s3 = boto3.resource('s3',aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        s3.Bucket(bucket_name).upload_file(file, file)


def webdav(file):
    user=config.get('WEBDAV','Username')
    password=config.get('WEBDAV','Password')
    url=config.get('WEBDAV','Server')
    remote_path=config.get('WEBDAV','RemotePath')
    port=config.getint('WEBDAV','Port',fallback=80)
    protocol=config.get('WEBDAV','Protocol',fallback='http')
    auth=config.get('WEBDAV','Auth',fallback='Basic')
    webdav= easywebdav.connect(
        host=url,
        port=port,
        protocol=protocol,
        path=remote_path,
        auth=auth_method.get(auth)(username=user,password=password)
    )
    webdav.upload(file,file)

def scp(file):
    host=config.get('SCP','Server')
    username=config.get('SCP','Username')
    password=config.get('SCP','Password')
    remote_path=config.get('SCP','RemotePath')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
    ssh.connect(host, username=username, password=password)
    with SCPClient(ssh.get_transport()) as scp:
        scp.put(file, remote_path)
    scp.close()

def sftp(file):
        host=config.get('SFTP','Server')
        username=config.get('SFTP','Username')
        password=config.get('SFTP','Password')
        remote_path=config.get('SFTP','RemotePath')
        if not remote_path.endswith('/'):
            remote_path += '/'
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.load_system_host_keys()
        client.connect(host, username=username, password=password)
        sftp_client = client.open_sftp()
        sftp_client.put(file, remote_path+file)
        sftp_client.close()

def web(file):
    host=config.get('WEB','Server',fallback='10.8.1.2')
    port=config.getint('WEB','Port',fallback=8000)
    URL="http://"+host+":"+str(port)+"/monitorize/upload-file/"
    hostname=os.uname().nodename
    with open(file, 'rb') as f:
        requests.post(f"{URL}{hostname}/", files={"file": f})
        
send_modes={
    "WEB": web,
    "FTP": ftp,
    "S3": s3,
    "SFTP": sftp,
    "WEBDAV": webdav,
    "SCP": scp
}