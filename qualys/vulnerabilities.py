import requests
import os
from datetime import date
from helpers.csv_parser import csv_a_json

def vulnerabilidades(auth, cliente):
    url = "https://qualysguard.qg2.apps.qualys.eu/api/2.0/fo/asset/host/vm/detection/"
    payload = {'action': 'list','status': 'Active','output_format': 'CSV_NO_METADATA'}
    headers = {'X-Requested-With': 'QualysPostman','Authorization': f'Basic {auth}'}
    try:
        response = requests.post(url, headers=headers, data=payload, verify=False)
        if response.status_code != 200:
            raise Exception(f"Error al descargar vulnerabilidades: {response.status_code}")
        ruta_directorio = os.path.join("Clientes", cliente, "Vulns")
        os.makedirs(ruta_directorio, exist_ok=True)
        nombre_base = f"{cliente}_vuln_{date.today().isoformat()}"
        ruta_csv = os.path.join(ruta_directorio, f"{nombre_base}.csv")
        ruta_json = os.path.join(ruta_directorio, f"{nombre_base}.json")
        with open(ruta_csv, 'wb') as archivo:
            archivo.write(response.content)
        print(f"[*] Datos descargados para vulnerabilidades: {ruta_csv}")
        csv_a_json(ruta_csv, ruta_json)
    except Exception as e:
        print(f"[!] Error en vulnerabilidades: {e}")