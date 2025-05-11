import os
import pyzipper
import configparser
import gnupg

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
    gpg = gnupg.GPG()
    with open(pcap_name, 'rb') as f:
        estado = gpg.encrypt_file(
            f,
            recipients=[gpgkey],
            output="GPG_encrypted_"+pcap_name,
            always_trust=True,
        )
    if estado.ok:
        os.remove(pcap_name)
        return "GPG_encrypted_"+pcap_name
    else:
        raise Exception("Error encrypting with GPG: " + estado.status)

ciphers_modes={
    "ZIP" : pcap_zip,
    "GPG" : pcap_gpg,
    "none" : lambda pcap_name : pcap_name
}