"""

Erase v1.0
Hector Alejandro Parada Blanco
Powered by parablan
2026

"""

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

def es_administrador():
    """Verifica si el proceso actual cuenta con privilegios de Administrador (Windows) o Root (Linux)."""
    if IS_LINUX:
        return os.geteuid() == 0
    elif IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False

def relanzar_como_administrador():
    """Solicita elevación UAC en Windows para relanzar el script con permisos de Administrador."""
    if IS_WINDOWS:
        try:
            import ctypes
            script_path = os.path.abspath(sys.argv[0])
            params = f'"{script_path}"'
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, os.path.dirname(script_path), 1
            )
            return ret > 32
        except Exception:
            return False
    return False


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

def sanitize_pdf_str(text):
    """Sanitiza cadenas de texto para evitar fallos de codificación en fuentes estándar de FPDF2."""
    if text is None:
        return ""
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def es_ruta_critica(path):
    """
    Punto 3: Verifica si una ruta corresponde a una unidad raíz o a directorios críticos del sistema operativo,
    bloqueando destrucciones accidentales catastróficas.
    """
    p_clean = str(path).strip().strip('"').strip("'")
    if IS_WINDOWS:
        # Detectar letras de unidad directas como "C:", "c:", "C:", "c:/"
        if len(p_clean) in (2, 3) and p_clean[0].isalpha() and p_clean[1] == ':' and (len(p_clean) == 2 or p_clean[2] in ('\\', '/')):
            drive_letter = p_clean[:2].upper()
            return True, f"Raíz completa de la unidad ({drive_letter}\\)"

    try:
        p_real = os.path.realpath(os.path.abspath(p_clean))
    except Exception:
        p_real = os.path.abspath(p_clean)

    if IS_WINDOWS:
        p_norm = p_real.rstrip('\\/').upper()
        drive, rest = os.path.splitdrive(p_norm)
        # Raíz de la unidad (ej. "C:" o "C:\")
        if not rest or rest in ['\\', '/'] or p_norm == drive:
            return True, f"Raíz completa de la unidad ({drive}\\)"

        sys_drive = os.environ.get('SystemDrive', 'C:').rstrip('\\/') + '\\'
        rutas_sistema = [
            os.environ.get('SystemRoot', 'C:\\Windows').upper(),
            os.environ.get('ProgramFiles', 'C:\\Program Files').upper(),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)').upper(),
            os.environ.get('ProgramData', 'C:\\ProgramData').upper(),
            (sys_drive + 'USERS').upper(),
        ]
        for bloqueada in rutas_sistema:
            if not bloqueada:
                continue
            b_norm = bloqueada.rstrip('\\/').upper()
            if p_norm == b_norm:
                return True, f"Directorio protegido del sistema ({bloqueada})"
            if b_norm in [os.environ.get('SystemRoot', 'C:\\Windows').upper(), os.environ.get('ProgramFiles', 'C:\\Program Files').upper(), os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)').upper()]:
                if p_norm.startswith(b_norm + '\\'):
                    return True, f"Subdirectorio de sistema operativo ({bloqueada})"
    else:
        p_norm = p_real.rstrip('/')
        if not p_norm or p_norm == '/':
            return True, "Directorio raíz del sistema (/)"
        rutas_bloqueadas = ['/bin', '/boot', '/dev', '/etc', '/lib', '/lib32', '/lib64', '/proc', '/root', '/sbin', '/sys', '/usr', '/var']
        for bloqueada in rutas_bloqueadas:
            if p_norm == bloqueada or p_norm.startswith(bloqueada + '/'):
                return True, f"Directorio protegido del sistema ({bloqueada})"

    return False, ""

def desmontar_volumenes_disco(drive_info):
    """
    Desmonta volúmenes y particiones para liberar bloqueos del sistema operativo
    SIN borrar tablas ni alterar los datos del disco físico.
    """
    if IS_LINUX:
        path = drive_info.get('Path', '')
        if path:
            try:
                subprocess.run(f"umount -f {path}* 2>/dev/null || true", shell=True)
            except Exception:
                pass
    elif IS_WINDOWS:
        drive_number = drive_info.get('Number', drive_info.get('Identifier'))
        if drive_number is not None:
            try:
                dismount_cmd = f'powershell -Command "Get-Partition -DiskNumber {drive_number} -ErrorAction SilentlyContinue | Dismount-Volume -ErrorAction SilentlyContinue"'
                subprocess.run(dismount_cmd, shell=True, capture_output=True)
            except Exception:
                pass

def revalidar_disco_fisico(selected_drive):
    """
    Punto 6: Re-consulta la lista actual de discos físicos inmediatamente antes de iniciar
    el proceso destructivo para asegurar que el índice, modelo y serial no hayan cambiado.
    """
    drives_actuales = list_physical_drives()
    target_ident = str(selected_drive.get('Identifier') or selected_drive.get('Number'))
    target_path = selected_drive.get('Path')
    target_serial = (selected_drive.get('Serial') or '').strip()
    target_model = (selected_drive.get('Model') or '').strip()

    disco_encontrado = None
    for d in drives_actuales:
        d_ident = str(d.get('Identifier') or d.get('Number'))
        if d.get('Path') == target_path or d_ident == target_ident:
            disco_encontrado = d
            break

    if not disco_encontrado:
        msg = f"El disco físico '{target_path}' (No. {target_ident}) ya no se encuentra presente en el sistema."
        escribir_log(f"\n[ALERTA DE SEGURIDAD CRÍTICA] {msg}")
        return False, msg

    if disco_encontrado.get('IsSystem') and not selected_drive.get('IsSystem'):
        msg = f"El disco físico No. {target_ident} ahora figura como DISCO DEL SISTEMA OPERATIVO."
        escribir_log(f"\n[ALERTA DE SEGURIDAD CRÍTICA] {msg}")
        return False, msg

    serial_actual = (disco_encontrado.get('Serial') or '').strip()
    if target_serial and target_serial.lower() not in ['unknown', 'desconocido', '']:
        if serial_actual and serial_actual.lower() not in ['unknown', 'desconocido', '']:
            if target_serial != serial_actual:
                msg = f"Discrepancia de Serial en disco {target_path}. Esperado: '{target_serial}', Actual: '{serial_actual}'"
                escribir_log(f"\n[ALERTA DE SEGURIDAD CRÍTICA] {msg}")
                return False, msg

    model_actual = (disco_encontrado.get('Model') or '').strip()
    if target_model and target_model.lower() not in ['unknown', 'desconocido', '']:
        if model_actual and model_actual.lower() not in ['unknown', 'desconocido', '']:
            if target_model != model_actual and target_model not in model_actual and model_actual not in target_model:
                msg = f"Discrepancia de Modelo en disco {target_path}. Esperado: '{target_model}', Actual: '{model_actual}'"
                escribir_log(f"\n[ALERTA DE SEGURIDAD CRÍTICA] {msg}")
                return False, msg

    return True, disco_encontrado

def create_pdf_report(directory, disk_info, hashes=None, status="EXITOSO", errores=None):
    """
    Punto 2: Genera el informe técnico de borrado seguro reflejando fielmente el estado real
    (EXITOSO, INCOMPLETO o FALLIDO) y documentando cualquier error o advertencia registrada.
    """
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
        pdf.cell(0, 5, text=f"Fecha y Hora: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Sistema operativo donde se realizó el borrado: {sanitize_pdf_str(plataforma)}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Unidad o directorio borrado: {sanitize_pdf_str(directory)}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text="Método híbrido: AES-GCM + DoD Short + Eliminación", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, text="| Información del dispositivo", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 5, text=f"Marca: {sanitize_pdf_str(disk_info.get('Brand', 'Unknown'))}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Modelo: {sanitize_pdf_str(disk_info.get('Model', 'Unknown'))}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Serial: {sanitize_pdf_str(disk_info.get('Serial', 'Unknown'))}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, text=f"Capacidad: {sanitize_pdf_str(disk_info.get('Size', 'Unknown'))}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(7)

        if hashes:
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 5, text="Verificación de Integridad (SHA-256 · Sectores Críticos MBR/GPT)", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=9)
            pdf.cell(0, 5, text=f"Hash Inicial (Cabeceras Originales): {hashes.get('initial')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 5, text=f"Hash Final   (Cabeceras Sanitizadas): {hashes.get('final')}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=8)
            pdf.cell(0, 4, text="Metodología: Verificación de destrucción de estructuras maestras según NIST SP 800-88 Rev. 1", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        
        pdf.set_font("Helvetica", "B", 12)
        if status == "EXITOSO":
            pdf.cell(0, 10, text="| DICTAMEN: El proceso de borrado seguro ha finalizado EXITOSAMENTE.", new_x="LMARGIN", new_y="NEXT", align='L')
        elif status == "INCOMPLETO":
            pdf.cell(0, 10, text="| DICTAMEN: El proceso ha finalizado con advertencias o INCOMPLETO.", new_x="LMARGIN", new_y="NEXT", align='L')
        else:
            pdf.cell(0, 10, text="| DICTAMEN: El proceso de borrado seguro ha FALLADO.", new_x="LMARGIN", new_y="NEXT", align='L')
        pdf.ln(2)

        if errores:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, text="Incidencias documentadas durante el proceso:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=8)
            for err in errores[:5]:
                pdf.cell(0, 4, text=f"· {sanitize_pdf_str(err)[:95]}", new_x="LMARGIN", new_y="NEXT")
            if len(errores) > 5:
                pdf.cell(0, 4, text=f"· ... y {len(errores) - 5} incidencias adicionales registradas en el log.", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 5, text=f"El detalle completo de los eventos y archivos procesados durante la sanitización se encuentra documentado en el archivo **{LOG_FILE}**, generado automáticamente. Este archivo contiene trazabilidad cronológica completa para fines de auditoría técnica y verificación de cumplimiento normativo.", markdown=True, align='J')

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
        log.write("ERASE \n")
        log.write("Powered by parablan \n\n")
        log.write(f"Fecha y Hora: {ahora}\n")
        log.write(f"Sistema operativo donde se realizó el borrado: {plataforma}\n")
        log.write(f"Unidad o directorio borrado: {directorio}\n")
        log.write("Método híbrido: AES-GCM + DoD Short + Borrado de archivos\n")
        log.write("="*50 + "\n\n")

def calcular_hash(path, algoritmo="sha256"):
    c = hashlib.new(algoritmo)
    with open(path, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            c.update(bloque)
    return c.hexdigest()

def escribir_patron(f, size, patron=None, bloque=4096):
    f.seek(0)
    last_log_time = time.time()
    patron_desc = "Aleatorio" if patron is None else f"0x{patron.hex()}"
    
    if patron is None:  # Aleatorio
        escritos = 0
        while escritos < size:
            to_write = min(bloque, size - escritos)
            f.write(os.urandom(to_write))
            escritos += to_write
            if time.time() - last_log_time > 5:
                progreso = (escritos / size) * 100
                print(f"Patrón {patron_desc} progreso: {progreso:.1f}% ({escritos / (1024**3):.1f} / {size / (1024**3):.1f} GB)", end='\r')
                last_log_time = time.time()
    else:
        bloque_bytes = patron * bloque
        escritos = 0
        while escritos < size:
            to_write = min(bloque, size - escritos)
            f.write(bloque_bytes[:to_write])
            escritos += to_write
            if time.time() - last_log_time > 5:
                progreso = (escritos / size) * 100
                print(f"Patrón {patron_desc} progreso: {progreso:.1f}% ({escritos / (1024**3):.1f} / {size / (1024**3):.1f} GB)", end='\r')
                last_log_time = time.time()

    if size > 100 * 1024 * 1024:
        print(f"Patrón {patron_desc} progreso: 100% ({size / (1024**3):.1f} GB)          ")

    try:
        f.flush()
        os.fsync(f.fileno())
    except Exception:
        pass

def cifrar_archivo_aes_gcm_inplace(path):
    """
    Cifra y sobrescribe el archivo directamente in-place (r+b),
    garantizando la alteración directa de los sectores del disco sin usar archivos temporales.
    Utiliza rotación periódica de claves efímeras para respetar el límite de 64 GiB de NIST SP 800-38D.
    """
    asegurar_escritura(path)
    backend = default_backend()
    rotation_interval = 8 * 1024 * 1024 * 1024  # Rotar clave cada 8 GiB
    bytes_with_key = 0
    
    def create_encryptor():
        k = os.urandom(32)
        n = os.urandom(12)
        return Cipher(algorithms.AES(k), modes.GCM(n), backend=backend).encryptor()
        
    encryptor = create_encryptor()
    
    try:
        with open(path, "r+b") as f:
            f.seek(0)
            offset = 0
            while True:
                if bytes_with_key >= rotation_interval:
                    encryptor = create_encryptor()
                    bytes_with_key = 0

                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                f.seek(offset)
                f.write(ct)
                offset += len(ct)
                bytes_with_key += len(ct)
                f.seek(offset)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
            
    except Exception as e:
        escribir_log(f"Error en cifrado in-place de {path}: {e}")
        raise e

def wipe_physical_drive_aes_gcm(path, size, chunk_size=1024*1024):
    """
    Cifra y sobrescribe el disco físico in-place generando un flujo pseudo-aleatorio criptográfico AES-256-GCM.
    Implementa rotación automática de clave y nonce cada 8 GiB para cumplir estrictamente con el límite
    máximo de cifrado de NIST SP 800-38D (64 GiB), permitiendo sanitizar discos de terabytes sin interrupciones.
    """
    backend = default_backend()
    rotation_interval = 8 * 1024 * 1024 * 1024  # Rotar clave y nonce cada 8 GiB
    bytes_with_key = 0
    
    def create_encryptor():
        k = os.urandom(32)
        n = os.urandom(12)
        return Cipher(algorithms.AES(k), modes.GCM(n), backend=backend).encryptor()

    encryptor = create_encryptor()
    last_log_time = time.time()

    # Importante: buffering=0 para evitar Errno 22 (Invalid argument) en discos físicos
    with open(path, "rb+", buffering=0) as f:
        f.seek(0)  # Asegurar inicio
        zeros = b'\x00' * chunk_size
        offset = 0
        
        while offset < size:
            # Rotar clave y nonce si se alcanza el umbral de 8 GiB
            if bytes_with_key >= rotation_interval:
                encryptor = create_encryptor()
                bytes_with_key = 0

            remaining = size - offset
            if remaining < chunk_size:
                chunk_data = b'\x00' * remaining
                ct = encryptor.update(chunk_data)
                f.write(ct)
                offset += remaining
                break
            
            ct = encryptor.update(zeros)
            f.write(ct)
            offset += chunk_size
            bytes_with_key += chunk_size

            # Notificar progreso cada 5 segundos
            if time.time() - last_log_time > 5:
                progreso = (offset / size) * 100
                print(f"AES-GCM progreso: {progreso:.1f}% ({offset / (1024**3):.1f} / {size / (1024**3):.1f} GB)", end='\r')
                last_log_time = time.time()

        print(f"AES-GCM progreso: 100% ({size / (1024**3):.1f} GB)          ")
        try:
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            pass

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
    Usa diskpart y PowerShell para desmontar volúmenes, limpiar particiones y liberar bloqueos del SO en Windows.
    """
    import tempfile
    # Desmontar volúmenes activos en PowerShell para liberar bloqueos de archivos abiertos
    try:
        dismount_cmd = f'powershell -Command "Get-Partition -DiskNumber {drive_number} -ErrorAction SilentlyContinue | Dismount-Volume -ErrorAction SilentlyContinue"'
        subprocess.run(dismount_cmd, shell=True, capture_output=True)
    except Exception:
        pass

    script_content = f"""select disk {drive_number}
attributes disk clear readonly
clean
rescan
"""
    script_path = os.path.join(tempfile.gettempdir(), f"diskpart_clean_{drive_number}_{os.getpid()}.txt")
    try:
        escribir_log(f"Preparando disco {drive_number} (Liberando bloqueos con Diskpart)...")
        with open(script_path, "w", encoding="ascii") as f:
            f.write(script_content)
        
        # Ejecutar diskpart
        subprocess.run(f'diskpart /s "{script_path}"', check=True, capture_output=True, shell=True)
        time.sleep(2) # Esperar a que el SO actualice el estado del disco
        escribir_log("Disco limpiado y desbloqueado correctamente.")
    except Exception as e:
        escribir_log(f"Advertencia: Error preparando disco con diskpart: {e}")
        # Intento secundario con PowerShell Clear-Disk si diskpart falla
        try:
            ps_clear = f'powershell -Command "Clear-Disk -Number {drive_number} -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue"'
            subprocess.run(ps_clear, shell=True, capture_output=True)
            time.sleep(2)
        except Exception:
            pass
    finally:
        if os.path.exists(script_path):
            try:
                os.remove(script_path)
            except Exception:
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
    # Los dispositivos físicos (\\.\PhysicalDriveN en Windows) exigen offsets alineados al sector;
    # un offset desalineado provoca [Errno 22] Invalid argument. 4096 cubre sectores de 512 y 4K.
    alineacion = 4096
    sospechosos = 0
    successful_reads = 0
    failed_reads = 0
    
    try:
        with open(path, "rb", buffering=0) as f:
            for i in range(samples):
                # Offset distribuido a lo largo del disco y alineado al límite de sector
                offset = (size // samples) * i
                offset -= offset % alineacion
                try:
                    f.seek(offset)
                    data = f.read(min(sample_size, size - offset))
                    
                    if not data:
                        failed_reads += 1
                        escribir_log(f"Advertencia: Lectura vacía en offset {offset}")
                        continue
                    
                    successful_reads += 1
                    
                    # Verificar que no sea todo ceros o todo unos (patrones sospechosos)
                    if data == b'\x00' * len(data):
                        escribir_log(f"ADVERTENCIA: Patrón de ceros detectado en offset {offset}")
                        sospechosos += 1
                    elif data == b'\xFF' * len(data):
                        escribir_log(f"ADVERTENCIA: Patrón de unos detectado en offset {offset}")
                        sospechosos += 1
                except Exception as read_error:
                    failed_reads += 1
                    escribir_log(f"Advertencia: No se pudo leer sector en offset {offset}: {read_error}")
                    continue
        
        if successful_reads == 0:
            escribir_log("ERROR: No se pudo leer ningún sector; la verificación no pudo realizarse.")
            return False
        if failed_reads > 0:
            escribir_log(f"Verificación INCOMPLETA: {successful_reads}/{samples} sectores leídos, {failed_reads} lecturas fallidas.")
            return False
        if sospechosos > 0:
            escribir_log(f"Verificación completada con {sospechosos} patrones sospechosos en {successful_reads} lecturas")
            return False
        escribir_log(f"Verificación completada: {successful_reads}/{samples} sectores leídos, sin patrones sospechosos")
        return True
    except Exception as e:
        escribir_log(f"ERROR durante verificación: {e}")
        return False

def calculate_critical_sectors_hash(path, size, algoritmo="sha256"):
    """
    Calcula el hash SHA-256 de los sectores críticos del disco físico (inicio y fin: MBR, GPT primario y backup).
    Permite verificar la destrucción irreversible de las estructuras maestras en menos de 1 segundo,
    siguiendo las directrices de verificación de NIST SP 800-88 Rev. 1 sin el cuello de botella
    de recorrer terabytes completos.
    """
    sector_size = 10 * 1024 * 1024  # 10 MB (cubre ampliamente MBR, tablas de partición GPT y VBR)
    c = hashlib.new(algoritmo)
    
    try:
        with open(path, "rb", buffering=0) as f:
            # 1. Cabecera inicial (MBR / GPT primario)
            f.seek(0)
            bloque_inicio = f.read(min(sector_size, size))
            c.update(bloque_inicio)
            
            # 2. Cola final (GPT backup al final del disco)
            if size > sector_size:
                offset_final = max(0, size - sector_size)
                f.seek(offset_final)
                bloque_final = f.read(size - offset_final)
                c.update(bloque_final)
                
        return c.hexdigest()
    except Exception as e:
        escribir_log(f"Error calculando hash de sectores críticos: {e}")
        return "ERROR_CALCULO_HASH"

def calculate_physical_drive_hash(path, size, algoritmo="sha256", full=False):
    """
    Calcula el hash criptográfico del disco físico.
    Por defecto (full=False) procesa los sectores críticos (primeros 10 MB y últimos 10 MB,
    abarcando MBR, GPT primario y GPT backup), tardando menos de un segundo y cumpliendo
    con la verificación ágil de NIST SP 800-88 Rev. 1.
    Si full=True, realiza lectura completa de todo el disco (puede demorar horas).
    """
    if not full:
        escribir_log(f"Calculando hash {algoritmo} de sectores críticos (MBR/GPT - Inicio y Fin)...")
        return calculate_critical_sectors_hash(path, size, algoritmo)

    escribir_log(f"Calculando hash {algoritmo} completo de disco (Tamaño: {size} bytes)...")
    c = hashlib.new(algoritmo)
    chunk_size = 4 * 1024 * 1024  # 4MB buffer para velocidad
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
        print("Hash progreso: 100%   ")
        return c.hexdigest()
    except Exception as e:
        escribir_log(f"Error calculando hash completo: {e}")
        return "ERROR_CALCULO_HASH"

def wipe_physical_drive_dod_short(drive_info):
    hashes = {'initial': 'N/A', 'final': 'N/A'}
    errores = []

    # Punto 6: Revalidar inmediatamente que el disco físico no haya cambiado antes de proceder
    valido, resultado = revalidar_disco_fisico(drive_info)
    if not valido:
        escribir_log(f"\n[ERROR CRÍTICO] Seguridad de disco fallida: {resultado}")
        print(f"\n[ERROR CRÍTICO] Seguridad de disco fallida: {resultado}")
        return
    drive_info = resultado

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

    # Verificación previa obligatoria de permisos de escritura a bajo nivel
    try:
        with open(path, "rb+", buffering=0):
            pass
    except PermissionError:
        escribir_log(f"\n[ERROR CRÍTICO] Acceso denegado a '{path}'.")
        escribir_log("En Windows se requiere obligatoriamente ejecutar la terminal como Administrador.")
        return
    except Exception as e:
        escribir_log(f"\n[ERROR CRÍTICO] No se pudo abrir '{path}': {e}")
        return

    # Desmontar volúmenes activos para liberar locks del SO SIN alterar ni limpiar tablas aún
    desmontar_volumenes_disco(drive_info)

    # Punto 1: Hash Inicial de Sectores Críticos ANTES de prepare_drive() o cualquier alteración
    escribir_log("Paso 1: Calculando Hash Inicial de sectores críticos (MBR/GPT - Estado Original)...")
    hashes['initial'] = calculate_physical_drive_hash(path, size)
    escribir_log(f"Hash Inicial: {hashes['initial']}")

    # Ahora sí: Preparar/Desbloquear el disco (diskpart clean / wipefs -a)
    escribir_log("Paso 2: Preparando disco y limpiando tablas de particiones...")
    prepare_drive(drive_info)

    # Paso 3: Sobrescritura inicial de sectores críticos (MBR/GPT)
    escribir_log("Paso 3: Sobrescritura inicial de sectores críticos (MBR/GPT)...")
    try:
        wipe_critical_sectors(path, size)
    except Exception as e:
        msg = f"Fallo en sobrescritura inicial de sectores críticos: {e}"
        escribir_log(msg)
        errores.append(msg)

    # Paso 4: Cifrado AES-GCM In-place con rotación cada 8 GiB
    try:
        escribir_log("Paso 4/6: Cifrado AES-GCM (Destructivo)...")
        wipe_physical_drive_aes_gcm(path, size)
        escribir_log("Cifrado AES-GCM completado.")
    except Exception as e:
        msg = f"Error en paso AES-GCM: {e}"
        escribir_log(msg)
        errores.append(msg)

    # Paso 5: Pasadas DoD Short (0x00, 0xFF, Aleatorio)
    patrones = [b"\x00", b"\xFF", None]
    try:
        with open(path, "rb+", buffering=0) as f:
            for i, patron in enumerate(patrones, start=1):
                if patron is None:
                    escribir_log(f"Paso 5/6 (DoD Pasada {i}/3): Aleatorio...")
                else:
                    escribir_log(f"Paso 5/6 (DoD Pasada {i}/3): Patrón 0x{patron.hex()}...")
                escribir_patron(f, size, patron, bloque=1024*1024)
    except Exception as e:
        msg = f"Error en paso DoD: {e}"
        escribir_log(msg)
        errores.append(msg)
    
    # Paso 6: Sobrescribir sectores críticos NUEVAMENTE
    escribir_log("Paso 6/6: Sobrescritura final de sectores críticos...")
    try:
        wipe_critical_sectors(path, size)
    except Exception as e:
        msg = f"Fallo en sobrescritura final de sectores críticos: {e}"
        escribir_log(msg)
        errores.append(msg)

    # Limpieza final de estructuras para que el SO actualice la tabla
    escribir_log("Limpieza y rescan final de tabla de particiones...")
    prepare_drive(drive_info)

    # Punto 8: Hash Final tomado como ÚLTIMO PASO de escritura definitiva (después de todo prepare_drive)
    escribir_log("Calculando Hash Final definitivo (Estado Final Inmutable)...")
    hashes['final'] = calculate_physical_drive_hash(path, size)
    escribir_log(f"Hash Final: {hashes['final']}")

    # Verificación de ausencia de patrones en disco (Solo lectura)
    verif_ok = verify_disk_wiped(path, size)
    if not verif_ok:
        errores.append("Verificación posterior fallida o incompleta (ver log para detalles)")

    escribir_log("=== Proceso de disco completo ===")
    
    # Punto 2: Determinar estado real de la operación
    if not errores:
        status = "EXITOSO"
    elif len(errores) >= 2:
        status = "FALLIDO"
    else:
        status = "INCOMPLETO"

    create_pdf_report(target_name, disk_info, hashes=hashes, status=status, errores=errores)

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
    disk_info = get_disk_info(directorio)
    errores = []
    
    for root, dirs, files in os.walk(directorio, topdown=False):
        # Archivos
        for file in files:
            path = os.path.join(root, file)
            try:
                wipe_dod_short(path)
            except Exception as e:
                msg = f"Error eliminando archivo {path}: {e}"
                escribir_log(msg)
                errores.append(msg)
        # Subdirectorios
        for d in dirs:
            subdir = os.path.join(root, d)
            try:
                asegurar_escritura(subdir)
                os.rmdir(subdir)
                escribir_log(f"Subdirectorio eliminado: {subdir}")
            except Exception as e:
                msg = f"No se pudo eliminar subdirectorio {subdir}: {e}"
                escribir_log(msg)
                errores.append(msg)
    # Carpeta raíz
    try:
        asegurar_escritura(directorio)
        os.rmdir(directorio)
        escribir_log(f"Carpeta raíz eliminada: {directorio}")
    except Exception as e:
        msg = f"No se pudo eliminar la carpeta raíz '{directorio}': {e}"
        escribir_log(msg)
        errores.append(msg)
        
    escribir_log("=== Proceso completo ===")
    
    # Punto 2: Rastrear estado real
    status = "EXITOSO" if not errores else "INCOMPLETO"
    create_pdf_report(directorio, disk_info, status=status, errores=errores)

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

Version: 1.0.1
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
        # Punto 3: Limpiar espacios y comillas, verificar rutas críticas y solicitar confirmación
        ruta_raw = input("Ruta del directorio a borrar: ")
        ruta = ruta_raw.strip().strip('"').strip("'")
        
        if not ruta:
            print("No se especificó ninguna ruta.")
        elif not os.path.exists(ruta):
            print(f"Ruta no encontrada: {ruta}")
        elif not os.path.isdir(ruta):
            print(f"La ruta especificada no es un directorio: {ruta}")
        else:
            es_critica, motivo = es_ruta_critica(ruta)
            if es_critica:
                print("\n" + "!" * 70)
                print(f"¡ACCESO DENEGADO POR SEGURIDAD! {motivo}")
                print("El sistema no permite borrar carpetas raíz o protegidas del sistema operativo.")
                print("!" * 70)
            else:
                total_archivos = 0
                total_bytes = 0
                for r, _, f_list in os.walk(ruta):
                    total_archivos += len(f_list)
                    for f_nom in f_list:
                        try:
                            total_bytes += os.path.getsize(os.path.join(r, f_nom))
                        except Exception:
                            pass
                tam_mb = total_bytes / (1024 * 1024)
                tam_str = f"{tam_mb/1024:.2f} GB" if tam_mb >= 1024 else f"{tam_mb:.2f} MB"

                print("\n" + "=" * 70)
                print(f"DIRECTORIO SELECCIONADO: {ruta}")
                print(f"Total de archivos detectados: {total_archivos}")
                print(f"Tamaño estimado: {tam_str}")
                print("ADVERTENCIA: Esta acción destruirá irreversiblemente los archivos")
                print("mediante cifrado AES-GCM + DoD Short de 3 pasadas.")
                print("=" * 70)
                confirm = input("\nEscriba 'CONFIRMAR' para autorizar el borrado seguro: ").strip()
                if confirm == "CONFIRMAR":
                    wipe_directory(ruta)
                else:
                    print("Operación cancelada por el usuario.")
            
    elif opcion == "2":
        if not es_administrador():
            print("\n" + "=" * 70)
            print("¡ATENCIÓN! ACCESO DENEGADO - SE REQUIEREN PERMISOS DE ADMINISTRADOR")
            print("Para acceder y borrar discos físicos completos es OBLIGATORIO")
            print("ejecutar este script con privilegios de Administrador (Root en Linux).")
            print("=" * 70)
            if IS_WINDOWS:
                resp = input("\n¿Desea relanzar el script como Administrador automáticamente? (S/N): ").strip().lower()
                if resp in ['s', 'si', 'y', 'yes']:
                    if relanzar_como_administrador():
                        print("Solicitud de elevación enviada. Se abrirá una nueva ventana...")
                        sys.exit(0)
                    else:
                        print("No se pudo elevar privilegios automáticamente.")
            elif IS_LINUX:
                print("Por favor, ejecute el script con:")
                print("  sudo python3 erase.py")
            input("\nPor favor, ejecute la terminal como Administrador. Presione ENTER para salir...")
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
            print("\n!!! ADVERTENCIA !!!")
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
