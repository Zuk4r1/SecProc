import psutil
import hashlib
import requests
import os
import sys
import tempfile
import ctypes
from ctypes import wintypes
from tabulate import tabulate

# ---------- Banner ----------
print(r"""
  ____         ____  ____             ____     
 / ___|  ___  / ___||  _ \ _ __ ___  / ___|   
 \___ \ / _ \| |    | |_) | '__/ _ \| | 
  ___) |  __/| |    |  __/| | | (_) | |
 |____/ \___|\____| |_|   |_|  \___/ \____|                                      
   SecProc - Escáner de Procesos con VirusTotal
	Autor: 🐉@Zuk4r1
""")

def get_sha256(file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def is_digitally_signed(file_path):
    try:
        wintrust = ctypes.WinDLL("wintrust.dll")
        WinVerifyTrust = wintrust.WinVerifyTrust
        WinVerifyTrust.argtypes = (wintypes.HWND, wintypes.LPCGUID, wintypes.LPVOID)
        WinVerifyTrust.restype = wintypes.LONG

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", wintypes.LPCGUID),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", wintypes.LPVOID),
                ("pSIPClientData", wintypes.LPVOID),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
            ]

        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_STATEACTION_VERIFY = 0x00000001
        WTD_STATEACTION_CLOSE = 0x00000002
        WTD_SAFER_FLAG = 0x00000100

        WINTRUST_ACTION_GENERIC_VERIFY_V2 = ctypes.c_buffer(
            b"\xaac\xb4\xde\x00\xc0\xd0\x1a\xaa\x00\xc0\x4f\xc2\xaa\xbb"
        )

        file_info = WINTRUST_FILE_INFO(
            ctypes.sizeof(WINTRUST_FILE_INFO),
            file_path,
            None,
            None,
        )

        data = WINTRUST_DATA(
            ctypes.sizeof(WINTRUST_DATA),
            None,
            None,
            WTD_UI_NONE,
            WTD_REVOKE_NONE,
            WTD_CHOICE_FILE,
            ctypes.pointer(file_info),
            WTD_STATEACTION_VERIFY,
            None,
            None,
            WTD_SAFER_FLAG,
            0,
        )

        result = WinVerifyTrust(
            0,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(data),
        )

        # Cerrar handle
        WinVerifyTrust(
            0,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(WINTRUST_DATA(
                ctypes.sizeof(WINTRUST_DATA),
                None, None,
                WTD_UI_NONE,
                WTD_REVOKE_NONE,
                WTD_CHOICE_FILE,
                ctypes.pointer(file_info),
                WTD_STATEACTION_CLOSE,
                None,
                None,
                WTD_SAFER_FLAG,
                0
            )),
        )

        return result == 0
    except Exception:
        return False

def check_virustotal(api_key, file_hash):
    if not file_hash:
        return "No hash"
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
            total = sum(data['data']['attributes']['last_analysis_stats'].values())
            return f"{positives}/{total}"
        elif response.status_code == 404:
            return "No encontrado"
        else:
            return f"Error {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

def is_unusual_path(file_path):
    suspicious_folders = [
        tempfile.gettempdir().lower(),
        os.path.expanduser("~\\AppData\\Local").lower(),
        os.path.expanduser("~\\AppData\\Roaming").lower()
    ]
    file_path_lower = file_path.lower()
    return any(folder in file_path_lower for folder in suspicious_folders)

def main():
    if sys.platform != "win32":
        print("Este script solo funciona en Windows.")
        sys.exit(1)

    api_key = input("Introduce tu API key de VirusTotal: ").strip()
    print("\n[+] Escaneando procesos...\n")

    report = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            exe = proc.info['exe']

            if exe and os.path.exists(exe):
                sha256 = get_sha256(exe)
                signed = "Sí" if is_digitally_signed(exe) else "No"
                unusual = "Sí" if is_unusual_path(exe) else "No"
                vt_result = check_virustotal(api_key, sha256)

                report.append([pid, name, exe, signed, unusual, vt_result])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    headers = ["PID", "Nombre", "Ruta", "Firmado", "Inusual", "VT"]

    print(tabulate(report, headers=headers, tablefmt="grid", maxcolwidths=[6, 20, 50, 8, 8, 10]))

    with open("resultados.txt", "w", encoding="utf-8") as f:
        f.write(tabulate(report, headers=headers, tablefmt="grid"))

    print("\n[+] Reporte guardado como 'resultados.txt'")

if __name__ == "__main__":
    main()
