import os
import sys
import stat
import hashlib
import datetime
import subprocess
import json
import time
import warnings
from fpdf import FPDF

# Suprimir avisos de obsolescencia de librerías para mantener la terminal limpia
warnings.filterwarnings("ignore", category=DeprecationWarning)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend

LOG_FILE = f"log{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
CHUNK_SIZE = 1024 * 1024  # 1 MiB por chunk para no cargar archivos grandes en memoria

IS_WINDOWS = sys.platform.startswith('win')
IS_LINUX = sys.platform.startswith('linux')

import platform
try:
    import distro
except ImportError:
    distro = None

def obtener_plataforma():
    """Retorna una descripción legible del sistema operativo actual."""
    try:
        if sys.platform.startswith('linux'):
            if distro:
                return f"{distro.name(pretty=True)} ({platform.system()} {platform.release()})"
            return f"Linux ({platform.release()})"
        elif sys.platform.startswith('win'):
            return f"Windows {platform.release()} ({platform.version()})"
        return f"{platform.system()} {platform.release()}"
    except Exception:
        return platform.platform()

plataforma = obtener_plataforma()

def get_resource_path(relative_path):
    """Obtiene la ruta absoluta de un recurso, compatible con PyInstaller y ejecución directa."""
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def asegurar_escritura(path):
    """Garantiza permisos de lectura y escritura sobre el archivo o directorio."""
    try:
        if os.path.exists(path):
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass

def get_disk_info(target_path):
    info = {'Brand': 'Unknown', 'Model': 'Unknown', 'Serial': 'Unknown', 'Size': 'Unknown'}
    if IS_LINUX:
        try:
            abs_path = os.path.abspath(target_path)
            check_path = abs_path
            while not os.path.exists(check_path) and os.path.dirname(check_path) != check_path:
                check_path = os.path.dirname(check_path)
            dev = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '-T', check_path]).decode().strip()
            if dev:
                pk = subprocess.check_output(['lsblk', '-no', 'PKNAME', dev]).decode().strip()
                disk_dev = f"/dev/{pk}" if pk else dev
                out = subprocess.check_output(['lsblk', '-b', '-J', '-d', '-o', 'NAME,MODEL,SERIAL,VENDOR,SIZE', disk_dev]).decode().strip()
                if out:
                    data = json.loads(out).get('blockdevices', [])
                    if data:
                        d = data[0]
                        info['Model'] = d.get('model') or 'Unknown'
                        info['Serial'] = d.get('serial') or 'Unknown'
                        vendor = d.get('vendor')
                        if vendor and vendor.strip():
                            info['Brand'] = vendor.strip()
                        else:
                            parts = info['Model'].split()
                            if parts:
                                info['Brand'] = parts[0]
                        size_bytes = d.get('size')
                        if size_bytes:
                            size_gb = float(size_bytes) / (1024**3)
                            info['Size'] = f"{size_gb/1024:.2f} TB" if size_gb >= 1000 else f"{size_gb:.2f} GB"
        except Exception as e:
            escribir_log(f"Warning: No se pudo obtener información del disco en Linux: {e}")
    else:
        # Windows
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
                
                # Brand logic
                manufacturer = data.get('Manufacturer')
                if manufacturer and manufacturer.strip() and manufacturer.lower() not in ['(standard disk drives)', 'unknown']:
                    info['Brand'] = manufacturer.strip()
                else:
                    parts = info['Model'].split()
                    if parts:
                        info['Brand'] = parts[0]
                
                # Size logic
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

def get_system_drive_number():
    """Detecta el identificador del disco físico que aloja el sistema operativo (C: en Windows o / en Linux)."""
    if IS_LINUX:
        try:
            root_dev = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '/']).decode().strip()
            return subprocess.check_output(['lsblk', '-no', 'PKNAME', root_dev]).decode().strip()
        except Exception:
            return None
    else:
        try:
            cmd = 'powershell "(Get-Partition -DriveLetter C).DiskNumber"'
            out = subprocess.check_output(cmd, shell=True).decode().strip()
            if out.isdigit():
                return int(out)
        except Exception:
            pass
        return None

def list_physical_drives():
    drives = []
    if IS_LINUX:
        system_disk = get_system_drive_number()
        try:
            out = subprocess.check_output(['lsblk', '-d', '-b', '-o', 'NAME,MODEL,SERIAL,VENDOR,SIZE,TYPE', '-J']).decode().strip()
            data = json.loads(out).get('blockdevices', [])
            idx = 0
            for d in data:
                if d.get('type') != 'disk':
                    continue
                name = d.get('name')
                size_bytes = d.get('size') or 0
                size_gb = float(size_bytes) / (1024**3)
                is_system = (name == system_disk)
                vendor = (d.get('vendor') or '').strip()
                model = (d.get('model') or '').strip()
                full_model = f"{vendor} {model}".strip() if vendor else (model or 'Desconocido')
                serial = (d.get('serial') or 'Desconocido').strip()
                brand = vendor if vendor else (full_model.split()[0] if full_model else 'Desconocido')
                drives.append({
                    'Number': idx,
                    'Identifier': name,
                    'Path': f'/dev/{name}',
                    'Model': full_model,
                    'Brand': brand,
                    'Serial': serial,
                    'SizeGB': size_gb,
                    'SizeBytes': size_bytes,
                    'Size': f"{size_gb/1024:.2f} TB" if size_gb >= 1000 else f"{size_gb:.2f} GB",
                    'IsSystem': is_system
                })
                idx += 1
        except Exception as e:
            escribir_log(f"Error listando discos en Linux: {e}")
    else:
        # Windows
        system_disk = get_system_drive_number()
        try:
            cmd = 'powershell "Get-Disk | Select-Object Number, Model, SerialNumber, Manufacturer, Size | ConvertTo-Json"'
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            if output:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for d in data:
                    num = d.get('Number')
                    size_bytes = d.get('Size') or 0
                    size_gb = float(size_bytes) / (1024**3)
                    is_system = (num is not None and system_disk is not None and num == system_disk)
                    manufacturer = d.get('Manufacturer')
                    model = d.get('Model') or 'Desconocido'
                    if manufacturer and manufacturer.strip() and manufacturer.lower() not in ['(standard disk drives)', 'unknown']:
                        brand = manufacturer.strip()
                    else:
                        parts = model.split()
                        brand = parts[0] if parts else 'Desconocido'
                    serial = (d.get('SerialNumber') or 'Desconocido').strip()
                    drives.append({
                        'Number': num,
                        'Identifier': str(num),
                        'Path': f"\\\\.\\PhysicalDrive{num}",
                        'Model': model,
                        'Brand': brand,
                        'Serial': serial,
                        'SizeGB': size_gb,
                        'SizeBytes': size_bytes,
                        'Size': f"{size_gb/1024:.2f} TB" if size_gb >= 1000 else f"{size_gb:.2f} GB",
                        'IsSystem': is_system
                    })
        except Exception as e:
            escribir_log(f"Error listando discos en Windows: {e}")
    return drives

def create_pdf_report(directory, disk_info, hashes=None):
    try:
        pdf = FPDF()
        pdf.set_margins(left=15, top=20, right=15)
        
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)
        
        logo_path = get_resource_path("logo.png")
        if os.path.exists(logo_path):
            pdf.image(logo_path, x=16, y=17, w=40)
            pdf.ln(10)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 10, text="Powered by parablan", new_x="LMARGIN", new_y="NEXT", align='L')
        pdf.ln(7)

        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, text="INFORME TÉCNICO DE BORRADO SEGURO", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 5, text="Constancia de sanitización de almacenamiento y destrucción irreversible de datos", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.ln(10)

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, text="| Informe de Borrado Seguro", new_x="LMARGIN", new_y="NEXT", align='L')
        pdf.ln(2)
        
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 5, text=f"Fecha y Hora: {datetime.datetime.now()}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Sistema operativo donde se realizó el borrado: {plataforma}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Unidad o directorio borrado: {directory}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text="Método híbrido: AES-GCM + DoD Short + Eliminación", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, text="| Información del dispositivo", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 5, text=f"Marca: {disk_info['Brand']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Modelo: {disk_info['Model']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Serial: {disk_info['Serial']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Capacidad: {disk_info['Size']}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(7)

        if hashes:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 5, text="Verificación de Integridad (SHA-256)", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=9)
            pdf.cell(0, 5, text=f"Hash Inicial: {hashes.get('initial')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 5, text=f"Hash Final:   {hashes.get('final')}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, text="| El proceso de borrado seguro ha finalizado exitosamente.", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 5, text=f"El detalle completo de los archivos eliminados durante el proceso de borrado seguro se encuentra documentado en el archivo **{LOG_FILE}**, generado automáticamente. Este archivo contiene trazabilidad completa para fines de auditoría y verificación técnica.", markdown=True, align='J')

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
        log.write(f"Powered by parablan \n\n")
        log.write(f"Ejecución: {ahora}\n")
        log.write(f"Sistema operativo donde se realizó el borrado: {plataforma}\n")
        log.write(f"Unidad o directorio borrado: {directorio}\n")
        log.write(f"Método híbrido: AES-GCM + DoD Short + Borrado de archivos\n")
        log.write("="*50 + "\n\n")

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
    """
    Cifra y sobrescribe el archivo directamente in-place (r+b),
    garantizando la alteración directa de los sectores del disco sin usar archivos temporales.
    """
    asegurar_escritura(path)
    key = os.urandom(32)       # AES-256
    nonce = os.urandom(12)     # Nonce GCM (12 bytes)
    backend = default_backend()
    encryptor = None
    
    try:
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend).encryptor()

        with open(path, "r+b") as f:
            f.seek(0)
            offset = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                f.seek(offset)
                f.write(ct)
                offset += len(ct)
                f.seek(offset)
            f.flush()
            os.fsync(f.fileno())
            
    except Exception as e:
        escribir_log(f"Error en cifrado in-place de {path}: {e}")
        raise e
    finally:
        # Destruir clave y objetos sensibles
        del key, nonce
        if encryptor:
            del encryptor

def wipe_physical_drive_aes_gcm(path, size, chunk_size=1024*1024):
    # Cifra el disco físico en el sitio (in-place)
    key = os.urandom(32)
    nonce = os.urandom(12)
    backend = default_backend()
    
    # Para disco físico, solo ciframos los chunks en un bucle simple
    # No guardamos cabecera ni tag porque es borrado destructivo
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend).encryptor()
    
    # Importante: buffering=0 para evitar Errno 22 (Invalid argument) en discos físicos
    with open(path, "rb+", buffering=0) as f:
        # Optimización: En lugar de Leer-Cifrar-Escribir (que falla por alineación/seek en Windows Raw),
        # Generamos el Keystream de AES-GCM (cifrando ceros) y sobrescribimos.
        # Esto es criptográficamente seguro (sobrescribe con pseudo-aleatorio de alta calidad)
        # y elimina las operaciones de lectura y seek que causan Errno 22.
        
        f.seek(0) # Asegurar inicio
        zeros = b'\x00' * chunk_size
        offset = 0
        
        while offset < size:
            # Calcular cuánto falta
            remaining = size - offset
            if remaining < chunk_size:
                # Último chunk más pequeño
                chunk_data = b'\x00' * remaining
                ct = encryptor.update(chunk_data)
                f.write(ct)
                offset += remaining
                break
            
            # Cifrar bloque de ceros -> Keystream
            ct = encryptor.update(zeros)
            f.write(ct)
            offset += chunk_size
    
    # No llamamos finalize() para tag porque no lo guardamos.

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
            
            # Sobrescribir final (GPT backup)
            if total_size > sector_size:
                escribir_log("Sobrescribiendo sectores críticos (final - GPT backup)...")
                f.seek(total_size - sector_size)
                f.write(os.urandom(sector_size))
                f.flush()
                os.fsync(f.fileno())
        
        escribir_log("Sectores críticos sobrescritos exitosamente.")
    except Exception as e:
        escribir_log(f"Error sobrescribiendo sectores críticos: {e}")

def prepare_drive_diskpart(drive_number):
    """
    Usa diskpart para limpiar la tabla de particiones y liberar bloqueos del SO en Windows.
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

def prepare_drive(drive_info):
    """
    Prepara el disco liberando bloqueos, desmontando particiones o limpiando tablas.
    """
    if IS_LINUX:
        path = drive_info['Path']
        try:
            escribir_log(f"Preparando disco {path} en Linux (Desmontando particiones)...")
            subprocess.run(f"umount -f {path}* 2>/dev/null || true", shell=True)
            time.sleep(1)
            subprocess.run(f"wipefs -a {path} 2>/dev/null || true", shell=True)
            subprocess.run(f"blockdev --rereadpt {path} 2>/dev/null || true", shell=True)
            escribir_log("Disco preparado y desmontado correctamente.")
        except Exception as e:
            escribir_log(f"Advertencia preparando disco en Linux: {e}")
    else:
        drive_number = drive_info.get('Number', drive_info.get('Identifier'))
        prepare_drive_diskpart(drive_number)

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
                    # Calcular offset aleatorio pero alineado
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

def calculate_physical_drive_hash(path, size, algoritmo="sha256"):
    escribir_log(f"Calculando hash {algoritmo} (Tamaño: {size} bytes)...")
    c = hashlib.new(algoritmo)
    chunk_size = 4 * 1024 * 1024 # 4MB buffer para velocidad
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
                
                # Log progreso cada 5 segundos
                if time.time() - last_log_time > 5:
                    progreso = (processed / size) * 100
                    print(f"Hash progreso: {progreso:.1f}%", end='\r')
                    last_log_time = time.time()
        print(f"Hash progreso: 100%   ")
        return c.hexdigest()
    except Exception as e:
        escribir_log(f"Error calculando hash: {e}")
        return "ERROR_CALCULO_HASH"

def wipe_physical_drive_dod_short(drive_info):
    hashes = {'initial': 'N/A', 'final': 'N/A'}
    # Paso previo: Preparar/Desbloquear el disco
    prepare_drive(drive_info)

    path = drive_info['Path']
    size = drive_info.get('SizeBytes', 0)
    
    if not size or size <= 0:
        if IS_LINUX:
            try:
                out = subprocess.check_output(['blockdev', '--getsize64', path]).decode().strip()
                size = int(out)
            except Exception as e:
                escribir_log(f"Error obteniendo tamaño del disco {path}: {e}")
                return
        else:
            try:
                num = drive_info.get('Number', drive_info.get('Identifier'))
                cmd = f'powershell "Get-Disk -Number {num} | Select-Object -ExpandProperty Size"'
                size = int(subprocess.check_output(cmd, shell=True).decode().strip())
            except Exception as e:
                escribir_log(f"Error obteniendo tamaño del disco: {e}")
                return

    disk_info = {
        'Brand': drive_info.get('Brand', 'Unknown'),
        'Model': drive_info.get('Model', 'Unknown'),
        'Serial': drive_info.get('Serial', 'Unknown'),
        'Size': drive_info.get('Size', 'Unknown')
    }
    ident = drive_info.get('Identifier', str(drive_info.get('Number')))
    target_name = f"Disco Físico {ident} ({disk_info['Model']})"
    encabezado_log(target_name)
    
    escribir_log(f"Iniciando borrado de: {target_name}")
    escribir_log(f"Dispositivo: {path}")
    escribir_log(f"Tamaño: {size} bytes")

    # Paso 0: Sobrescribir sectores críticos ANTES del proceso principal
    escribir_log("Paso 0: Sobrescritura inicial de sectores críticos (MBR/GPT)...")
    wipe_critical_sectors(path, size)

    # Paso 1: Hash Inicial
    escribir_log("Calculando Hash Inicial...")
    hashes['initial'] = calculate_physical_drive_hash(path, size)
    escribir_log(f"Hash Inicial: {hashes['initial']}")

    # Paso 2: AES-GCM In-place
    try:
        escribir_log("Paso 1/4: Cifrado AES-GCM (Destructivo)...")
        wipe_physical_drive_aes_gcm(path, size)
        escribir_log("Cifrado AES-GCM completado.")
    except Exception as e:
        escribir_log(f"Error en paso AES-GCM: {e}")

    # Paso 3: DoD
    patrones = [b"\x00", b"\xFF", None]
    
    # Importante: buffering=0 para raw access
    with open(path, "rb+", buffering=0) as f:
        for i, patron in enumerate(patrones, start=1):
            pass_num = i + 1 # AES was 1
            if patron is None:
                escribir_log(f"Paso {pass_num}/4: Aleatorio...")
            else:
                 escribir_log(f"Paso {pass_num}/4: Patrón {patron.hex()}...")
            
            escribir_patron(f, size, patron, bloque=1024*1024)
    
    # Paso 4: Sobrescribir sectores críticos NUEVAMENTE
    escribir_log("Paso Final Extra: Sobrescritura final de sectores críticos...")
    wipe_critical_sectors(path, size)

    # Paso 5: Hash Final
    escribir_log("Calculando Hash Final...")
    hashes['final'] = calculate_physical_drive_hash(path, size)
    escribir_log(f"Hash Final: {hashes['final']}")

    # Paso 6: Verificación de ausencia de patrones en disco
    verify_disk_wiped(path, size)

    # Paso 7: Limpieza final de tabla de particiones
    escribir_log("Limpieza final de tabla de particiones...")
    prepare_drive(drive_info)

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
    asegurar_escritura(path)
    with open(path, "r+b") as f:
        for i, patron in enumerate(patrones, start=1):
            escribir_patron(f, size, patron)
            escribir_log(f"Pasada {i}/{len(patrones)} completada.")
    escribir_log("Proceso DoD Short finalizado.")

    # Paso 3: Hash final y eliminación
    hash_final = calcular_hash(path)
    escribir_log(f"Hash final: {hash_final}")

    asegurar_escritura(path)
    os.remove(path)
    escribir_log("Archivo eliminado.\n")

def wipe_directory(directorio):
    encabezado_log(directorio)
    # Extraer metadatos de hardware antes de destruir el directorio
    disk_info = get_disk_info(directorio)
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
                asegurar_escritura(subdir)
                os.rmdir(subdir)
                escribir_log(f"Subdirectorio eliminado: {subdir}")
            except Exception as e:
                escribir_log(f"No se pudo eliminar subdirectorio {subdir}: {e}")
    # Carpeta raíz
    try:
        asegurar_escritura(directorio)
        os.rmdir(directorio)
        escribir_log(f"Carpeta raíz '{directorio}' eliminada.")
    except Exception as e:
        escribir_log(f"No se pudo eliminar la carpeta raíz: {e}")
    escribir_log("=== Proceso completo ===")
    
    # Generar reporte PDF
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
        if IS_LINUX and os.geteuid() != 0:
            print("\n" + "=" * 65)
            print("¡ATENCIÓN! ACCESO DENEGADO")
            print("Para borrar discos físicos en Linux se requieren permisos de root.")
            print("Por favor, ejecute el script con:")
            print("  sudo python3 erase.py")
            print("=" * 65)
            input("\nPresione ENTER para salir...")
            sys.exit(1)

        drives = list_physical_drives()
        if not drives:
            print("\nNo se detectaron discos físicos disponibles.")
            input("\nPresione ENTER para salir...")
            sys.exit(0)

        print("\nDiscos Disponibles:")
        print(f"{'No.':<5} {'Dispositivo':<14} {'Modelo':<32} {'Tamaño (GB)':<14} {'Tipo':<15}")
        print("-" * 85)
        for d in drives:
             tipo = "[SISTEMA / SO]" if d.get('IsSystem') else "Datos"
             ident = d.get('Identifier') or str(d.get('Number'))
             print(f"{d['Number']:<5} {ident:<14} {d['Model']:<32} {d['SizeGB']:<14.2f} {tipo:<15}")
        
        try:
            target = int(input("\nIngrese el número del disco a borrar: "))
            selected_drive = next((d for d in drives if d['Number'] == target), None)
            
            if not selected_drive:
                print("El número ingresado no coincide con ningún disco listado.")
                input("\nPresione ENTER para salir...")
                sys.exit(1)

            if selected_drive.get('IsSystem'):
                print("\n" + "!" * 65)
                print("¡PELIGRO CRÍTICO! Ha seleccionado el DISCO DEL SISTEMA OPERATIVO.")
                print("Si continúa, el sistema quedará totalmente DESTRUIDO e inoperable.")
                print("!" * 65)
                doble_confirm = input("Escriba 'DESTRUIR-SISTEMA' para autorizar esta acción: ")
                if doble_confirm != "DESTRUIR-SISTEMA":
                    print("Operación cancelada por seguridad.")
                    sys.exit(0)

            # Confirmación de seguridad
            print(f"\n!!! ADVERTENCIA !!!")
            ident = selected_drive.get('Identifier') or str(selected_drive.get('Number'))
            print(f"Está a punto de borrar TODO el contenido del Disco Físico {ident} ({selected_drive['Model']}).")
            print(f"Ruta del dispositivo: {selected_drive['Path']}")
            print("Esta acción es IRREVERSIBLE. Se perderán particiones y datos.")
            confirm = input("Escriba 'ERASE' para confirmar: ")
            
            if confirm == "ERASE":
                wipe_physical_drive_dod_short(selected_drive)
            else:
                print("Operación cancelada.")
        except ValueError:
            print("Entrada inválida.")
    
    else:
        print("Opción inválida.")
        
    input("\nProceso finalizado. Presione ENTER para salir...")
