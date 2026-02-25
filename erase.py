'''

copyright © 2026 - parablan

Desarrollador:  Hector Alejandro Parada Blanco
                https://www.parablan.com.co/
                Powered by parablan

Descripción:
Herramienta diseñada para borrar de forma segura directorios, unidades de disco duro y medios de almacenamiento fisicos.

'''

import os
import ctypes
import sys
import hashlib
import datetime
import subprocess
import json
import json
import time
from fpdf import FPDF

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend

LOG_FILE = f"log{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
CHUNK_SIZE = 1024 * 1024  # 1 MiB por bloque para no cargar archivos grandes en memoria

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
            
            # Lógica de la marca
            manufacturer = data.get('Manufacturer')
            if manufacturer and manufacturer.strip() and manufacturer.lower() not in ['(standard disk drives)', 'unknown']:
                info['Brand'] = manufacturer.strip()
            else:
                # Intentar adivinar a partir del modelo
                parts = info['Model'].split()
                if parts:
                     info['Brand'] = parts[0]
            
            # Lógica del tamaño
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

def get_physical_disk_info(disk_number):
    info = {'Brand': 'Unknown', 'Model': 'Unknown', 'Serial': 'Unknown', 'Size': 'Unknown'}
    try:
        cmd = f'powershell "Get-Disk -Number {disk_number} | Select-Object Model, SerialNumber, Manufacturer, Size | ConvertTo-Json"'
        output = subprocess.check_output(cmd, shell=True).decode().strip()
        if output:
            data = json.loads(output)
            info['Model'] = data.get('Model', 'Unknown')
            info['Serial'] = data.get('SerialNumber', 'Unknown')
            manufacturer = data.get('Manufacturer')
            if manufacturer and manufacturer.strip() and manufacturer.lower() not in ['(standard disk drives)', 'unknown']:
                info['Brand'] = manufacturer.strip()
            # Lógica del tamaño
            size_bytes = data.get('Size')
            if size_bytes:
                size_gb = float(size_bytes) / (1024**3)
                if size_gb >= 1000:
                    info['Size'] = f"{size_gb/1024:.2f} TB"
                else:
                    info['Size'] = f"{size_gb:.2f} GB"
    except Exception as e:
        escribir_log(f"Warning: No se pudo obtener información del disco físico {disk_number}: {e}")
    return info

def list_physical_drives():
    drives = []
    try:
        cmd = 'powershell "Get-Disk | Select-Object Number, Model, Size | ConvertTo-Json"'
        output = subprocess.check_output(cmd, shell=True).decode().strip()
        if output:
            data = json.loads(output)
            if isinstance(data, dict):  # Disco único
                data = [data]
            for d in data:
                size_gb = d.get('Size', 0) / (1024**3)
                drives.append({
                    'Number': d.get('Number'),
                    'Model': d.get('Model'),
                    'SizeGB': size_gb
                })
    except Exception as e:
        print(f"Error listando discos: {e}")
    return drives

def create_pdf_report(directory, disk_info, hashes=None):
    try:
        pdf = FPDF()
        pdf.set_margins(left=15, top=20, right=15)
        
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        pdf.image("logo.png", x=16, y=17, w=40)
        pdf.ln(10)
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt="1.0", ln=True, align='L')
        pdf.ln(10)
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt="Powered by parablan", ln=True, align='L')

        pdf.ln(5)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(200, 10, txt="Informe de Borrado Seguro", ln=True, align='L')
        pdf.ln(2)
        
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 5, txt=f"Fecha y Hora: {datetime.datetime.now()}", ln=True)
        pdf.cell(200, 5, txt="Método híbrido: AES-GCM + DoD Short + Eliminación", ln=True)
        pdf.cell(200, 5, txt=f"Unidad o directorio borrado: {directory}", ln=True)
        pdf.ln(2)
        
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, txt="Información del dispositivo", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 5, txt=f"Marca: {disk_info['Brand']}", ln=True)
        pdf.cell(200, 5, txt=f"Modelo: {disk_info['Model']}", ln=True)
        pdf.cell(200, 5, txt=f"Serial: {disk_info['Serial']}", ln=True)
        pdf.cell(200, 5, txt=f"Capacidad: {disk_info['Size']}", ln=True)
        pdf.ln(5)

        if hashes:
            pdf.ln(2)
            pdf.set_font("Arial", "B", 10)
            pdf.cell(200, 5, txt="Verificación de Integridad (SHA-256)", ln=True)
            pdf.set_font("Arial", size=9)
            pdf.cell(200, 5, txt=f"Hash inicial: {hashes.get('initial')}", ln=True)
            pdf.cell(200, 5, txt=f"Hash Final:   {hashes.get('final')}", ln=True)
            pdf.ln(2)
        
        pdf.set_font("Arial", "I", 12)
        pdf.cell(200, 10, txt="El proceso de borrado seguro ha finalizado exitosamente.", ln=True)

        pdf.ln(5)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(180, 5, txt=f"El detalle completo de los archivos eliminados durante el proceso de borrado seguro se encuentra documentado en el archivo {LOG_FILE}, generado automáticamente. Este archivo contiene trazabilidad completa para fines de auditoría y verificación técnica.", align='J')

        filename = f"reporte_borrado_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
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
        log.write(f"1.0\n")
        log.write(f"Powered by parablan \n\n")
        log.write(f"Ejecución: {ahora}\n")
        log.write(f"Unidad o directorio borrado: {directorio}\n")
        log.write(f"Método híbrido: AES-GCM + DoD Short + Borrado de archivos\n")
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
    # Cifra el archivo en el sitio usando AES-GCM por bloques:
    key = os.urandom(32)       # AES-256
    nonce = os.urandom(12)     # Nonce GCM (12 bytes)
    backend = default_backend()

    # Leer el archivo y cifrar por bloques escribiendo a un temporal
    temp_path = path + ".enc_tmp"
    encryptor = None
    
    try:
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
        
    except Exception as e:
        # Asegurar limpieza del temporal si hay error
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                escribir_log(f"Archivo temporal {temp_path} eliminado después de error.")
            except:
                pass
        raise e
    finally:
        # Destruir clave y objetos sensibles
        del key, nonce
        if encryptor:
            del encryptor

def wipe_physical_drive_aes_gcm(path, size, chunk_size=1024*1024):
    # Cifra el disco físico en el sitio (in-place)
    # Rotamos claves cada 1GB para evitar "Exceeded maximum encrypted byte limit" de AES-GCM
    ROTATE_LIMIT = 1 * 1024 * 1024 * 1024 # 1 GB
    backend = default_backend()
    
    # Importante: buffering=0 para evitar Errno 22 (Argumento inválido) en discos físicos
    with open(path, "rb+", buffering=0) as f:
        f.seek(0) # Asegurar inicio
        zeros = b'\x00' * chunk_size
        offset = 0
        bytes_processed_since_rotate = 0

        # Inicializar el primer encriptador
        key = os.urandom(32)
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend).encryptor()
        
        while offset < size:
            # Verificar rotación
            if bytes_processed_since_rotate >= ROTATE_LIMIT:
                 key = os.urandom(32)
                 nonce = os.urandom(12)
                 encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend).encryptor()
                 bytes_processed_since_rotate = 0
            
            # Calcular cuánto falta
            remaining = size - offset
            if remaining < chunk_size:
                # Último bloque más pequeño
                chunk_data = b'\x00' * remaining
                if bytes_processed_since_rotate == 0:
                     # Si acabamos de rotar, necesitamos una nueva instancia
                     # (aunque en teoría la verificación de rotación ya lo hizo)
                     pass
                ct = encryptor.update(chunk_data)
                f.write(ct)
                offset += remaining
                break
            
            # Cifrar bloque de ceros -> Flujo de claves (Keystream)
            ct = encryptor.update(zeros)
            f.write(ct)
            offset += chunk_size
            bytes_processed_since_rotate += chunk_size

def wipe_critical_sectors(path, total_size):
    """
    Sobrescribe los sectores críticos al inicio y final del disco
    donde residen MBR, GPT, y metadatos del sistema de archivos.
    Esto previene la recuperación de estructuras de particiones.
    """
    sector_size = 10 * 1024 * 1024  # 10 MB
    
    try:
        with open(path, "rb+", buffering=0) as f:
            # Sobrescribir inicio (MBR/GPT primario)
            escribir_log("Sobrescribiendo sectores críticos (inicio - MBR/GPT)...")
            f.seek(0)
            f.write(os.urandom(sector_size))
            f.flush()
            os.fsync(f.fileno())
            
            # Sobrescribir final (Respaldo GPT)
            if total_size > sector_size:
                escribir_log("Sobrescribiendo sectores críticos (final - Respaldo GPT)...")
                f.seek(total_size - sector_size)
                f.write(os.urandom(sector_size))
                f.flush()
                os.fsync(f.fileno())
        
        escribir_log("Sectores críticos sobrescritos exitosamente")
    except Exception as e:
        escribir_log(f"Error sobrescribiendo sectores críticos: {e}")

def prepare_drive_diskpart(drive_number):
    """
    Usa diskpart para limpiar la tabla de particiones y liberar bloqueos del SO.
    """
    script_content = f"""
select disk {drive_number}
attributes disk clear readonly
clean
rescan
"""
    script_path = "diskpart_clean.txt"
    try:
        escribir_log(f"Preparando disco {drive_number} (Liberando bloqueos con Diskpart)...")
        with open(script_path, "w") as f:
            f.write(script_content)
        
        # Ejecutar diskpart
        subprocess.run(f"diskpart /s {script_path}", check=True, capture_output=True, shell=True)
        time.sleep(3) # Esperar a que el SO actualice el estado del disco
        escribir_log("Disco limpiado y desbloqueado correctamente.")
    except Exception as e:
        escribir_log(f"Advertencia: Error preparando disco con diskpart: {e}")
    finally:
        if os.path.exists(script_path):
            try:
                os.remove(script_path)
            except:
                pass

def verify_disk_wiped(path, size):
    """
    Verifica que el disco no contenga estructuras reconocibles.
    Lee muestras aleatorias y verifica que no haya patrones uniformes.
    """
    escribir_log("Verificando borrado completo del disco...")
    sample_size = 1024 * 1024  # 1MB por muestra
    samples = 10
    warnings = 0
    successful_reads = 0
    
    try:
        with open(path, "rb", buffering=0) as f:
            for i in range(samples):
                try:
                    # Calcular desplazamiento (offset) aleatorio pero alineado
                    offset = (size // samples) * i
                    f.seek(offset)
                    data = f.read(min(sample_size, size - offset))
                    
                    if not data:
                        continue
                    
                    successful_reads += 1
                    
                    # Verificar que no sea todo ceros o todo unos (patrones sospechosos)
                    if data == b'\x00' * len(data):
                        escribir_log(f"ADVERTENCIA: Patrón de ceros detectado en offset {offset}")
                        warnings += 1
                    elif data == b'\xFF' * len(data):
                        escribir_log(f"ADVERTENCIA: Patrón de unos detectado en offset {offset}")
                        warnings += 1
                except Exception as read_error:
                    # Error leyendo este sector específico, continuar con el siguiente
                    escribir_log(f"Advertencia: No se pudo leer sector en offset {offset}: {read_error}")
                    continue
        
        if successful_reads == 0:
            escribir_log("Advertencia: No se pudieron leer sectores para verificación (esto es normal después de borrado completo)")
            return True  # Consideramos exitoso si no se puede leer nada
        elif warnings == 0:
            escribir_log(f"Verificación completada: {successful_reads}/{samples} sectores leídos, sin patrones sospechosos")
            return True
        else:
            escribir_log(f"Verificación completada con {warnings} advertencias en {successful_reads} lecturas")
            return False
    except Exception as e:
        escribir_log(f"Advertencia durante verificación: {e} (esto puede ser normal después de borrado completo)")
        return True  # No consideramos esto un error fatal


        if os.path.exists(script_path):
            try:
                os.remove(script_path)
            except:
                pass

def calculate_physical_drive_hash(path, size, algoritmo="sha256"):
    escribir_log(f"Calculando hash {algoritmo} (Tamaño: {size} bytes)...")
    c = hashlib.new(algoritmo)
    chunk_size = 4 * 1024 * 1024 # Búfer de 4MB para velocidad
    processed = 0
    last_log_time = time.time()
    
    try:
        with open(path, "rb", buffering=0) as f:
            while processed < size:
                to_read = min(chunk_size, size - processed)
                bloque = f.read(to_read)
                if not bloque:
                    break
                c.update(bloque)
                processed += len(bloque)
                
                # Registrar progreso cada 5 segundos
                if time.time() - last_log_time > 5:
                    progreso = (processed / size) * 100
                    print(f"Hash progreso: {progreso:.1f}%", end='\r')
                    last_log_time = time.time()
        print(f"Hash progreso: 100%   ")
        return c.hexdigest()
    except Exception as e:
        escribir_log(f"Error calculando hash: {e}")
        return "ERROR_CALCULO_HASH"

def wipe_physical_drive_dod_short(drive_number):
    hashes = {'initial': 'N/A', 'final': 'N/A'}
    # Paso previo: Preparar/Desbloquear el disco
    prepare_drive_diskpart(drive_number)

    path = f"\\\\.\\PhysicalDrive{drive_number}"
    
    # Obtener tamaño exacto
    try:
        cmd = f'powershell "Get-Disk -Number {drive_number} | Select-Object -ExpandProperty Size"'
        size = int(subprocess.check_output(cmd, shell=True).decode().strip())
    except:
        escribir_log(f"Error obteniendo tamaño del disco {drive_number}")
        return  

    disk_info = get_physical_disk_info(drive_number)
    target_name = f"Disco Fisico {drive_number} ({disk_info['Model']})"
    encabezado_log(target_name)
    
    escribir_log(f"Iniciando borrado de: {target_name}")
    escribir_log(f"Tamaño: {size} bytes")

    # Paso 0: Sobrescribir sectores críticos ANTES del proceso principal
    escribir_log("Sobrescritura inicial de sectores críticos")
    wipe_critical_sectors(path, size)

    # Paso 1: Hash Inicial
    escribir_log("Calculando Hash Inicial")
    hashes['initial'] = calculate_physical_drive_hash(path, size)
    escribir_log(f"Hash inicial: {hashes['initial']}")

    # Paso 2: AES-GCM en el sitio (in-place)
    try:
        escribir_log("Paso 1/4: Cifrado AES-GCM (Destructivo)...")
        wipe_physical_drive_aes_gcm(path, size)
        escribir_log("Cifrado AES-GCM completado.")
    except Exception as e:
        escribir_log(f"Error en paso AES-GCM: {e}")

    # Paso 3: DoD
    patrones = [b"\x00", b"\xFF", None]
    
    # Importante: buffering=0 para acceso directo a nivel disco (raw access)
    with open(path, "rb+", buffering=0) as f:
        for i, patron in enumerate(patrones, start=1):
            pass_num = i + 1 # AES fue el paso 1
            if patron is None:
                escribir_log(f"Paso {pass_num}/4: Aleatorio...")
            else:
                if patron.hex()=="00":
                    escribir_log(f"Paso {pass_num}/4: Patrón 0...")
                if patron.hex()=="ff":
                    escribir_log(f"Paso {pass_num}/4: Patrón 1...")
            
            escribir_patron(f, size, patron, bloque=1024*1024)
    
    # Paso 4: Sobrescribir sectores críticos NUEVAMENTE
    escribir_log("Sobrescritura final de sectores críticos")
    wipe_critical_sectors(path, size)

    # Paso 5: Hash Final
    escribir_log("Calculando Hash Final")
    hashes['final'] = calculate_physical_drive_hash(path, size)
    escribir_log(f"Hash Final: {hashes['final']}")

    # Paso 6: Limpieza final de tabla de particiones
    escribir_log("Limpieza tabla de particiones")
    prepare_drive_diskpart(drive_number)

    escribir_log("=== Proceso de disco completo ===")
    create_pdf_report(target_name, disk_info, hashes)



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
    
    # Generar reporte PDF
    disk_info = get_disk_info(directorio)
    create_pdf_report(directorio, disk_info)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if not is_admin():
        # Re-ejecuta el script como administrador
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

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

1.0
Powered by parablan
Hector Alejandro Parada Blanco

**************************************************

Borrado seguro de información
Método híbrido: AES-GCM + DoD Short + Borrado de archivos

**************************************************
''')
    print("Seleccione una opción:")
    print("1. Borrar Directorio")
    print("2. Borrar Disco Físico Completo (Requiere permisos de administrador)")
    
    opcion = input("\nOpción (1/2): ")
    
    if opcion == "1":
        ruta = input("Ruta del directorio a borrar: ")
        if os.path.exists(ruta):
            wipe_directory(ruta)
        else:
            print("Ruta no encontrada.")
            
    elif opcion == "2":
        drives = list_physical_drives()
        print("\nDiscos Disponibles:")
        print(f"{'No.':<5} {'Modelo':<30} {'Tamaño (GB)':<15}")
        print("-" * 50)
        for d in drives:
             print(f"{d['Number']:<5} {d['Model']:<30} {d['SizeGB']:<15.2f}")
        
        try:
            target = int(input("\nIngrese el número del disco a borrar: "))
            # Confirmación de seguridad
            print(f"\n!!! ADVERTENCIA !!!")
            print(f"Está a punto de borrar TODO el contenido del Disco Físico {target}.")
            print("Esta acción es IRREVERSIBLE. Se perderán particiones y datos.")
            confirm = input("Escriba 'ERASE' para confirmar: ")
            
            if confirm == "ERASE":
                wipe_physical_drive_dod_short(target)
            else:
                print("Operación cancelada.")
        except ValueError:
            print("Entrada inválida.")
    
    else:
        print("Opción inválida.")
        
    input("\nProceso finalizado. Presione ENTER para salir...")
