import requests
import xml.etree.ElementTree as ET
import json
import os
from datetime import date
from helpers.csv_parser import convertir_tipo


def host_list(user, passwd, cliente):
    url = "https://qualysguard.qg2.apps.qualys.eu/api/2.0/fo/asset/host/"
    headers = {'X-Requested-With': 'QualysPostman'}
    payload = {'action': 'list','details': 'All','show_tags': '0','truncation_limit': '0'}
    try:
        response = requests.post(url, headers=headers, data=payload, auth=(user, passwd), verify=False)
        if response.status_code != 200:
            raise Exception(f"Error al descargar hosts: {response.status_code} - {response.text[:300]}")
        root = ET.fromstring(response.text)
        hosts_data = []
        for host_elem in root.findall(".//HOST"):
            host = {}
            for child in host_elem:
                if child.tag:
                    text = child.text.strip() if child.text else None
                    host[child.tag] = convertir_tipo(text)
                for sub in child:
                    if sub.tag:
                        sub_text = sub.text.strip() if sub.text else None
                        host[sub.tag] = convertir_tipo(sub_text)
            hosts_data.append(host)
        if not hosts_data:
            print("[!] No se encontraron hosts en la respuesta.")
            return
        ruta_directorio = os.path.join("Clientes", cliente, "Hosts")
        os.makedirs(ruta_directorio, exist_ok=True)
        nombre_base = f"{cliente}_hosts_{date.today().isoformat()}"
        ruta_json = os.path.join(ruta_directorio, f"{nombre_base}.json")
        with open(ruta_json, 'w', encoding='utf-8') as f_json:
            json.dump(hosts_data, f_json, indent=4, ensure_ascii=False, default=str)
        print(f"[+] Listado de hosts guardado en: {ruta_json}")
    except Exception as e:
        print(f"[!] Error en host_list: {e}")