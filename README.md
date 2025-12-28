# ERASE

Herramienta diseñada como apoyo en la sanitización de medios de almacenamiento.

# Funcionamiento

Erase utiliza tres métodos para el borrado de información segura.

AES-GCM = Cifrando y generando una clave sobre el archivo
DoD Short = Variante simplificada del estándar de borrado de datos DoD 5220.22-M (realiza tres pasadas, sobrescribe con 0, 1 y finalmente patrones aleatorios)
Borrado = Eliminación del archivo
