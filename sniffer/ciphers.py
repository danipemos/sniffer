import os
import pyzipper
import configparser
import gnupg
import config_search
config=configparser.ConfigParser()
config.read(config_search.search_config())

def pcap_zip(pcap_name):
    zipkey=config.get('General','ZipKey',fallback="Secreto")
    zip_name= os.path.splitext(pcap_name)[0]+".zip"
    with pyzipper.AESZipFile(zip_name, 'w',compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES,allowZip64=True) as zip_file:
        zip_file.setpassword(zipkey.encode())
        zip_file.write(pcap_name,arcname=pcap_name)
    os.remove(pcap_name)
    return zip_name

def pcap_gpg(pcap_name):
    gpgkey = config.get('General', 'GPGKey')
    gpg_home = '/home/sniffer/.gnupg'

    if not os.path.isdir(gpg_home):
        os.makedirs(gpg_home, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=gpg_home)

    # Get only the filename, not the path
    base_name = os.path.basename(pcap_name)
    output_name = f"GPG_encrypted_{base_name}"

    # Save the encrypted file in the same directory as the original
    output_path = os.path.join(os.path.dirname(pcap_name), output_name)

    with open(pcap_name, 'rb') as f:
        estado = gpg.encrypt_file(
            f,
            recipients=[gpgkey],
            output=output_path,
            always_trust=True,
        )
    if estado.ok:
        os.remove(pcap_name)
        return output_path
    else:
        raise Exception("Error encrypting with GPG: " + estado.status)

ciphers_modes={
    "ZIP" : pcap_zip,
    "GPG" : pcap_gpg,
    "none" : lambda pcap_name : pcap_name
}