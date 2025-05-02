import os
import pyzipper
import configparser
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5

config=configparser.ConfigParser()
config.read('config.ini')

def pcap_zip(pcap_name):
    zipkey=config.get('General','ZipKey',fallback="Secreto")
    zip_name= os.path.splitext(pcap_name)[0]+".zip"
    with pyzipper.AESZipFile(zip_name, 'w',compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES,allowZip64=True) as zip_file:
        zip_file.setpassword(zipkey.encode())
        zip_file.write(pcap_name,arcname=pcap_name)
    os.remove(pcap_name)
    return zip_name

def pcap_gpg(pcap_name):
    gpgkey=config.get('General','GPGKey')
    with open(gpgkey, 'rb') as pubkey:
        public_key=RSA.import_key(pubkey.read())
    key=get_random_bytes(32)
    encripted_file= os.path.splitext(pcap_name)[0]+"/encripted.pcap"
    with open(pcap_name, 'rb') as pcap:
        data=pcap.read()
    os.makedirs(os.path.splitext(pcap_name)[0])

    iv=get_random_bytes(AES.block_size)
    cipher=AES.new(key, AES.MODE_CBC, iv)
    data_filled=pad(data,AES.block_size)
    encrypted_data=cipher.encrypt(data_filled)
    iv_file=os.path.splitext(pcap_name)[0]+"/iv.bin"

    with open(iv_file ,'w')as iv_file:
        iv_file.write(iv.hex())

    with open(encripted_file, 'wb') as encripted:
        encripted.write(encrypted_data)

    cipher=PKCS1_v1_5.new(public_key)
    encrypted_key=cipher.encrypt(key)

    encrypted_key_file = os.path.splitext(pcap_name)[0]+'/'+'encrypted_key.bin'
    with open(encrypted_key_file,'wb') as encripted_key_file:
        encripted_key_file.write(encrypted_key)
    
    with pyzipper.ZipFile("encrypted_"+os.path.splitext(pcap_name)[0]+".zip",'w',compression=pyzipper.ZIP_DEFLATED,allowZip64=True) as zip:
        for file in os.listdir(os.path.splitext(pcap_name)[0]+"/"):
            zip.write(os.path.splitext(pcap_name)[0]+"/"+file,arcname=file)
            os.remove(os.path.splitext(pcap_name)[0]+"/"+file)

    os.removedirs(os.path.splitext(pcap_name)[0]+"/")
    os.remove(pcap_name)
    return "encrypted_"+os.path.splitext(pcap_name)[0]+".zip"

ciphers_modes={
    "ZIP" : pcap_zip,
    "GPG" : pcap_gpg,
    "none" : lambda pcap_name : pcap_name
}