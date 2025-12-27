import os
import hashlib
import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend

LOG_FILE = "log.txt"
CHUNK_SIZE = 1024 * 1024  # 1 MiB por chunk
def escribir_log(mensaje):
    # Escribir mensaje en pantalla y en log.txt
    print(mensaje)
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(mensaje + "\n")

def encabezado_log(directorio):
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write("\n" + "="*50 + "\n")
        log.write(f"Ejecución: {ahora}\n")
        log.write(f"Directorio: {directorio}\n")
        log.write("="*50 + "\n")

def calcular_hash(path, algoritmo="sha256"):
    c = hashlib.new(algoritmo)
    with open(path, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            c.update(bloque)
    return c.hexdigest()

def escribir_patron(f, size, patron=None, bloque=4096):
    f.seek(0)
    if patron is None:  # Aleatorio
        escritos = 0
        while escritos < size:
            to_write = min(bloque, size - escritos)
            f.write(os.urandom(to_write))
            escritos += to_write
    else:
        bloque_bytes = patron * bloque
        escritos = 0
        while escritos < size:
            to_write = min(bloque, size - escritos)
            f.write(bloque_bytes[:to_write])
            escritos += to_write
    f.flush()
    os.fsync(f.fileno())

def cifrar_archivo_aes_gcm_inplace(path):
    # Cifra el archivo usando AES-GCM por chunks:
    key = os.urandom(32)       # AES-256
    nonce = os.urandom(12)     # Nonce GCM (12 bytes)
    backend = default_backend()

    # Leer el archivo y cifrar por chunks escribiendo a un temporal
    temp_path = path + ".enc_tmp"
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend).encryptor()

    with open(path, "rb") as fin, open(temp_path, "wb") as fout:
        # Cabecera: magic + nonce + reserva tag (16 bytes de ceros que actualizaremos al final)
        fout.write(b"ENC1")
        fout.write(nonce)
        fout.write(b"\x00" * 16)

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)
        encryptor.finalize()
        # Escribir tag final en la cabecera (posición fija: 4 + 12 = offset 16)
        fout.seek(4 + 12)
        fout.write(encryptor.tag)

    # Reemplazar el archivo original por el cifrado
    os.replace(temp_path, path)

    # Destruir clave y objetos
    del key, nonce, encryptor

def wipe_dod_short(path):
    nombre = os.path.basename(path)
    hash_inicial = calcular_hash(path)
    escribir_log(f"Archivo: {nombre}")
    escribir_log(f"Hash inicial: {hash_inicial}")

    # Paso 1: Cifrado efímero
    try:
        escribir_log("Cifrado AES-GCM efímero iniciado.")
        cifrar_archivo_aes_gcm_inplace(path)
        escribir_log("Cifrado AES-GCM efímero finalizado.")
    except Exception as e:
        escribir_log(f"Error cifrando {path}: {e}")

    # Paso 2: DoD Short (0x00, 0xFF, aleatorio)
    size = os.path.getsize(path)
    patrones = [b"\x00", b"\xFF", None]

    escribir_log("Proceso DoD Short iniciado.")
    with open(path, "r+b") as f:
        for i, patron in enumerate(patrones, start=1):
            escribir_patron(f, size, patron)
            escribir_log(f"Pasada {i}/{len(patrones)} completada.")
    escribir_log("Proceso DoD Short finalizado.")

    # Paso 3: Hash final y eliminación
    hash_final = calcular_hash(path)
    escribir_log(f"Hash final: {hash_final}")

    os.remove(path)
    escribir_log("Archivo eliminado.\n")

def wipe_directory(directorio):
    encabezado_log(directorio)
    for root, dirs, files in os.walk(directorio, topdown=False):
        # Archivos
        for file in files:
            path = os.path.join(root, file)
            try:
                wipe_dod_short(path)
            except Exception as e:
                escribir_log(f"Error con {path}: {e}")
        # Subdirectorios
        for d in dirs:
            subdir = os.path.join(root, d)
            try:
                os.rmdir(subdir)
                escribir_log(f"Subdirectorio eliminado: {subdir}")
            except Exception as e:
                escribir_log(f"No se pudo eliminar subdirectorio {subdir}: {e}")
    # Carpeta raíz
    try:
        os.rmdir(directorio)
        escribir_log(f"Carpeta raíz '{directorio}' eliminada.")
    except Exception as e:
        escribir_log(f"No se pudo eliminar la carpeta raíz: {e}")
    escribir_log("=== Proceso completo ===")

if __name__ == "__main__":
    print(r'''
**************************************************
 _______   _______   _______   _______   _______ 
(  ____ \ (  ____ ) (  ___  ) (  ____ \ (  ____ \
| (    \/ | (    )| | (   ) | | (    \/ | (    \/
| (__     | (____)| | (___) | | (_____  | (__    
|  __)    |     __) |  ___  | (_____  ) |  __)   
| (       | (\ (    | (   ) |       ) | | (      
| (____/\ | ) \ \__ | )   ( | /\____) | | (____/\
(_______/ |/   \__/ |/     \| \_______) (_______/

Powered by parablan
Hector Alejandro Parada Blanco

**************************************************

Borrado seguro de directorios     
Método Híbrido: AES-GCM + DoD Short

**************************************************

''')
    ruta = input("Directorio a eliminar: ")
    wipe_directory(ruta)
    input("\nProceso finalizado. Presione ENTER para salir...")
