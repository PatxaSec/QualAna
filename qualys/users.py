import requests
import xml.etree.ElementTree as ET
import json
import os
from datetime import date
from helpers.csv_parser import convertir_tipo

def qualys_users_list(user, passwd, cliente):
    url = "https://qualysguard.qg2.apps.qualys.eu/msp/user_list.php"
    headers = {'X-Requested-With': 'QualysPostman'}
    try:
        response = requests.post(url, headers=headers, auth=(user, passwd), verify=False)
        if response.status_code != 200:
            raise Exception(f"Error al descargar usuarios: {response.status_code} - {response.text[:300]}")
        root = ET.fromstring(response.text)
        users_data = []
        for user_elem in root.findall(".//USER"):
            user_dict = {}
            for child in user_elem:
                if child.tag:
                    user_dict[child.tag] = convertir_tipo(child.text.strip() if child.text else None)
            users_data.append(user_dict)
        if not users_data:
            print("[!] No se encontraron usuarios en la respuesta XML.")
            return
        ruta_directorio = os.path.join("Clientes", cliente, "Users")
        os.makedirs(ruta_directorio, exist_ok=True)
        nombre_base = f"{cliente}_users_{date.today().isoformat()}"
        ruta_json = os.path.join(ruta_directorio, f"{nombre_base}.json")
        with open(ruta_json, 'w', encoding='utf-8') as f_json:
            json.dump(users_data, f_json, indent=4, ensure_ascii=False, default=str)
        print(f"[+] {len(users_data)} usuarios guardados en: {ruta_json}")
    except Exception as e:
        print(f"[!] Error en users_list: {e}")