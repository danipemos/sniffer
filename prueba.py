import gnupg

# Inicializa el objeto GPG
gpg = gnupg.GPG()
# Ruta del archivo a cifrar
archivo_entrada = 'capture_20250505_153602.pcap'
archivo_salida = 'capture_20250505_153602.pcap.gpg'

# ID o email del destinatario cuya clave pública usarás
destinatario = 'danipemos@gmail.com'  # o key ID como 'ABC1234'

# Cifrar el archivo
with open(archivo_entrada, 'rb') as f:
    estado = gpg.encrypt_file(
        f,
        recipients=[destinatario],
        output=archivo_salida
    )

# Verifica si fue exitoso
if estado.ok:
    print("Archivo cifrado exitosamente.")
else:
    print("Error al cifrar:", estado.status)


with open(archivo_salida, 'rb') as f:
# Desencriptar el archivo
    estado = gpg.decrypt_file(f,output='capture_20250505_153602_decrypted.pcap', passphrase='jvbfdubgdfi')
# Verifica si fue exitoso
print (estado.status)
