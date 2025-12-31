import os
import hashlib
import datetime
import subprocess
import json
from fpdf import FPDF

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend

LOG_FILE = f"log{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
CHUNK_SIZE = 1024 * 1024  # 1 MiB por chunk para no cargar archivos grandes en memoria

def get_disk_info(target_path):
    info = {'Brand': 'Unknown', 'Model': 'Unknown', 'Serial': 'Unknown', 'Size': 'Unknown'}
    try:
        drive_letter = os.path.splitdrive(os.path.abspath(target_path))[0].replace(':', '')
        if not drive_letter:
             cmd = 'powershell "Get-Disk | Select-Object Model, SerialNumber, Manufacturer, Size | Select-Object -First 1 | ConvertTo-Json"'
        else:
             cmd = f'powershell "Get-Partition -DriveLetter {drive_letter} | Get-Disk | Select-Object Model, SerialNumber, Manufacturer, Size | ConvertTo-Json"'
        
        output = subprocess.check_output(cmd, shell=True).decode().strip()
        if output:
            data = json.loads(output)
            info['Model'] = data.get('Model', 'Unknown')
            info['Serial'] = data.get('SerialNumber', 'Unknown')
            
            # Marca del dispositivo
            manufacturer = data.get('Manufacturer')
            if manufacturer and manufacturer.strip() and manufacturer.lower() not in ['(standard disk drives)', 'unknown']:
                info['Brand'] = manufacturer.strip()
            else:
                # Modelo del dispositivo
                parts = info['Model'].split()
                if parts:
                     info['Brand'] = parts[0]
            
            # Tamaño
            size_bytes = data.get('Size')
            if size_bytes:
                size_gb = float(size_bytes) / (1024**3)
                if size_gb >= 1000:
                    info['Size'] = f"{size_gb/1024:.2f} TB"
                else:
                    info['Size'] = f"{size_gb:.2f} GB"

    except Exception as e:
        escribir_log(f"Warning: No se pudo obtener información del disco: {e}")
    return info

def create_pdf_report(directory, disk_info):
    try:
        pdf = FPDF()
        pdf.set_margins(left=15, top=20, right=15)
        
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        pdf.image("logo.png", x=16, y=17, w=40)
        pdf.ln(10)
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt="Powered by parablan", ln=True, align='L')

        pdf.ln(5)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, txt="Informe de Borrado Seguro", ln=True, align='L')
        pdf.ln(2)
        
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 5, txt=f"Fecha y hora: {datetime.datetime.now()}", ln=True)
        pdf.cell(200, 5, txt=f"Unidad o directorio borrado: {directory}", ln=True)
        pdf.cell(200, 5, txt=f"Versión de software: 1.0", ln=True)
        pdf.cell(200, 5, txt="Método híbrido: AES-GCM + DoD Short + Eliminación de archivos", ln=True)
        pdf.ln(2)
        
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, txt="Información del dispositivo", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 5, txt=f"Marca: {disk_info['Brand']}", ln=True)
        pdf.cell(200, 5, txt=f"Modelo: {disk_info['Model']}", ln=True)
        pdf.cell(200, 5, txt=f"Serial: {disk_info['Serial']}", ln=True)
        pdf.cell(200, 5, txt=f"Capacidad: {disk_info['Size']}", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "I", 12)
        pdf.cell(200, 10, txt="El proceso de borrado seguro ha finalizado exitosamente.", ln=True)

        pdf.ln(5)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(180, 5, txt=f"El detalle completo de los archivos eliminados durante el proceso de borrado seguro se encuentra documentado en el archivo {LOG_FILE}, generado automáticamente. Este archivo contiene trazabilidad completa para fines de auditoría y verificación técnica.", align='J')

        filename = f"informe_borrado_seguro_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(filename)
        escribir_log(f"Reporte PDF generado: {os.path.abspath(filename)}")
    except Exception as e:
        escribir_log(f"Error generando PDF: {e}")

def escribir_log(mensaje):
    # Escribir mensaje en pantalla y en log.txt
    print(mensaje)
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(mensaje + "\n")

def encabezado_log(directorio):
    ahora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write("\n" + "="*50 + "\n")
        log.write(f"ERASE \n")
        log.write(f"Powered by parablan \n\n")
        log.write(f"Ejecución: {ahora}\n")
        log.write(f"Unidad o directorio borrado: {directorio}\n")
        log.write(f"Versión de software: 1.0 \n")
        log.write(f"Método híbrido: AES-GCM + DoD Short + Eliminación de archivos\n")
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
    # Cifra el archivo en el sitio (in-place) usando AES-GCM por chunks:
    key = os.urandom(32)       # AES-256
    nonce = os.urandom(12)     # Nonce GCM (12 bytes)
    backend = default_backend()

    # Leer el archivo y cifrar por chunks escribiendo a un temporal
    temp_path = path + ".enc_tmp"
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend).encryptor()

    with open(path, "rb") as fin, open(temp_path, "wb") as fout:
        # Cabecera: magic + nonce + reserva tag
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
    
    # Generar reporte en formato PDF
    disk_info = get_disk_info(directorio)
    create_pdf_report(directorio, disk_info)

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

Versión: 1.0 
Powered by parablan
Hector Alejandro Parada Blanco

**************************************************

Borrado seguro de información
Método híbrido: AES-GCM + DoD Short + Eliminación de archivos

**************************************************

''')
    ruta = input("Unidad o directorio a borrar: ")
    wipe_directory(ruta)
    input("\nProceso finalizado. Presione ENTER para salir...")
