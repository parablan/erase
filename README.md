# ERASE

Herramienta diseñada como apoyo en el proceso de sanitización de medios de almacenamiento.

# Funcionamiento

Erase utiliza tres métodos para el borrado de información de forma segura.

AES-GCM = Cifrado y generación de clave dinamica sobre el archivo  
DoD Short = Variante simplificada del estándar de borrado de datos DoD 5220.22-M (realiza tres pasadas, sobrescribe con 0, 1 y finalmente patrones aleatorios).  
Borrado = Eliminación del archivo  

# Log

El sistema genera un log.txt con la información necesaria que soporte procesos de auditoría, grabando como encabezado la fecha y hora de ejecución, así como el nombre del directorio raíz indicado por el usuario.  

Ejemplo:  

Ejecución: 2025-12-26 23:41:43
Directorio: C:\Users\alejo\Downloads\Nueva carpeta

Posteriormente se indica el contenido del directorio y sub directorios a eliminar, indicando nombre del archivo, hash inicial, proceso AES-GCM, proceso DoD Short, hash final y la eliminación del archivo.   

Ejemplo  

Archivo: DOC-2025-10-31.docx  
Hash inicial: 3ece50079c9887f0dffec5762af2e6277248d1b8fc599f56e01f523a33721db2  
Cifrado AES-GCM efímero iniciado.  
Cifrado AES-GCM efímero finalizado.  
Proceso DoD Short iniciado.  
Pasada 1/3 completada.  
Pasada 2/3 completada.  
Pasada 3/3 completada.  
Proceso DoD Short finalizado.  
Hash final: 4a3425f81ecc71a056d3789f6745827ee6735caa1cca89b0d4241897f82a9ff1  
Archivo eliminado.  

Archivo: Git-2.52.0-64-bit.exe  
Hash inicial: d8de7a3152266c8bb13577eab850ea1df6dccf8c2aa48be5b4a1c58b7190d62c  
Cifrado AES-GCM efímero iniciado.  
Cifrado AES-GCM efímero finalizado.  
Proceso DoD Short iniciado.  
Pasada 1/3 completada.  
Pasada 2/3 completada.  
Pasada 3/3 completada.  
Proceso DoD Short finalizado.  
Hash final: f068254067e7271eea687cebdc3fc8931e350b5633c5f0b104fa124ca8794eac  
Archivo eliminado.  

Carpeta raíz 'C:\Users\alejo\Downloads\Nueva carpeta' eliminada.  
=== Proceso completo ===  
