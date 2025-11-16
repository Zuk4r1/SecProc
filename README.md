# 🛡️SecProc Escáner de Procesos con VirusTotal y Detección de Rutas Sospechosas

Este script en **Python** para Windows permite analizar todos los procesos en ejecución, verificar su firma digital, calcular su hash SHA256, consultar el estado del archivo en **VirusTotal**, y marcar aquellos que se ejecutan desde rutas inusuales.

## 🛠️ Funcionalidades
- Escaneo de todos los procesos activos en Windows.
- Cálculo del **hash SHA256** de cada ejecutable.
- Consulta en **VirusTotal** (requiere API Key).
- Verificación de **firma digital**.
- Detección de procesos ejecutándose desde rutas sospechosas (`Temp`, `AppData\Local`, `AppData\Roaming`).
- Generación de un **reporte detallado** (`resultados.txt`).

## 📦 Requisitos
- **Windows 10/11**
- **Python 3.x** instalado
- Módulos de Python:
```bash
py -m pip install psutil requests
```

```bash
py -m pip install pywin32
```

## ▶️ Uso
1. Clonar el repositorio:

```bash
git clone https://github.com/Zuk4r1/SecProc.git
cd SecProc
```
2. Ejecutar el script:

```bash
py SecProc.py
```

3. Introducir la API Key de VirusTotal cuando el script lo solicite.
Puedes obtener una API Key gratuita en: [virustotal](https://www.virustotal.com/gui/my-apikey)

4. Esperar a que finalice el análisis.
El reporte se guardará como reporte_procesos.txt en la misma carpeta.

## 📤 Ejemplo de salida

```bash
PID    Nombre                    Ruta                                                         Firmado    Inusual      VT
1234   chrome.exe                C:\Program Files\Google\Chrome\Application\chrome.exe        Sí         No          0/72 motores detectaron amenaza
4321   malware.exe               C:\Users\user\AppData\Local\Temp\malware.exe                 No         Sí          15/72 motores detectaron amenaza
```

## ☕ Apoya mis proyectos
Si te resultan útiles mis herramientas, considera dar una ⭐ en GitHub o invitarme un café. ¡Gracias!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/investigacq)  [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/yordansuarezrojas)


## 📝 Notas
* El script solo funciona en Windows.

* Una API Key gratuita de VirusTotal tiene un límite de consultas por minuto.

* Los resultados de VirusTotal dependen de la base de datos pública y pueden variar.

## ⚖️ Licencia
[MIT License](https://github.com/Zuk4r1/SecProc/blob/main/LICENSE). Puedes usar, modificar y distribuir este script libremente, citando la autoría original.

## ✍️ Autor

Creado con ❤️ por [@Zuk4r1](https://github.com/Zuk4r1), pentester con conocimiento en hacking forense y análisis de comportamiento de malware.

## 🎯 Propósito 

Herramienta de análisis y auditoría de procesos en Windows.
