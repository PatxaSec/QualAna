import requests
import urllib3
import json
import os
from datetime import date

def inventario(user, passwd, cliente):
    import requests as r_local, urllib3 as u_local
    u_local.disable_warnings(u_local.exceptions.InsecureRequestWarning)
    QUALYS_BASE_URL = "https://gateway.qg2.apps.qualys.eu"
    jwt_token = ""
    software_list = {}
    print(f"[*] Iniciando extracción de inventario para {cliente}...")
    try:
        auth_response = r_local.post(f"{QUALYS_BASE_URL}/auth", data={"username": user, "password": passwd, "token": "true"}, headers={"Content-Type": "application/x-www-form-urlencoded"}, verify=False)
    except Exception as e:
        print(f"[X] Error al conectar con Qualys (inventario): {e}")
        return
    if auth_response.status_code not in [200, 201]:
        print(f"[X] ERROR: Falló la autenticación para inventario ({auth_response.status_code})")
        return
    jwt_token = auth_response.text.strip()
    asset_url = f"{QUALYS_BASE_URL}/rest/2.0/search/am/asset?pageSize=300&includeFields=agent,agentId,assetName,operatingSystem"
    asset_response = r_local.post(asset_url, headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}, verify=False)
    if asset_response.status_code != 200:
        print(f"[X] ERROR: No se pudo obtener la lista de assets ({asset_response.status_code})")
        print(asset_response.text[:300])
        return
    try:
        asset_list = asset_response.json()['assetListData']['asset']
    except KeyError:
        print("[X] ERROR: La respuesta no contiene 'assetListData'.")
        print(json.dumps(asset_response.json(), indent=2))
        return
    asset_name_map = {}
    for asset in asset_list:
        asset_id = asset.get('assetId')
        asset_name = asset.get('assetName', 'Desconocido')
        os_cat = (asset.get('operatingSystem') or {}).get('category1', '')
        if os_cat == "Windows":
            asset_name_map[asset_id] = asset_name
    print(f"[*] {len(asset_name_map)} equipos Windows detectados.")
    for asset_id, asset_name in asset_name_map.items():
        api_url = f"{QUALYS_BASE_URL}/rest/2.0/get/am/asset?assetId={asset_id}&softwareType=Application&includeFields=software"
        api_response = r_local.get(api_url, headers={"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}, verify=False)
        if api_response.status_code != 200:
            print(f"[!] Error obteniendo software del agente {asset_id} ({api_response.status_code})")
            continue
        try:
            software_list_json = api_response.json()['assetListData']['asset'][0]['softwareListData']['software']
        except (KeyError, IndexError):
            continue
        for software in software_list_json:
            pname = software.get('productName', 'Desconocido')
            full = software.get('fullName', '')
            if pname not in software_list:
                software_list[pname] = {"Software Publisher": software.get('publisher', ''), "Software Category 1": software.get('category1', ''), "Software Category 2": software.get('category2', ''), "Software Authorization": software.get('authorization', ''), "General Count": 1, "versions": {}}
            else:
                software_list[pname]['General Count'] += 1
            if full not in software_list[pname]['versions']:
                software_list[pname]['versions'][full] = {"fullName": full, "count": 1, "hosts": [asset_name]}
            else:
                software_list[pname]['versions'][full]['count'] += 1
                if asset_name not in software_list[pname]['versions'][full]['hosts']:
                    software_list[pname]['versions'][full]['hosts'].append(asset_name)
    documentos = []
    for nombre, datos in software_list.items():
        for version, vdatos in datos.get("versions", {}).items():
            doc = {"Software": nombre, "Version": version, "Publisher": datos.get("Software Publisher"), "Category1": datos.get("Software Category 1"), "Category2": datos.get("Software Category 2"), "Authorization": datos.get("Software Authorization"), "GeneralCount": datos.get("General Count"), "VersionCount": vdatos.get("count"), "Hosts": vdatos.get("hosts", [])}
            documentos.append(doc)
    ruta_directorio = os.path.join("Clientes", cliente, "Inventario")
    os.makedirs(ruta_directorio, exist_ok=True)
    ruta_json = os.path.join(ruta_directorio, f"{cliente}_inventario_{date.today().isoformat()}.json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(documentos, f, indent=4, ensure_ascii=False, default=str)
    print(f"[+] Inventario guardado en formato lista: {ruta_json}")
    print(f"[+] Total de entradas: {len(documentos)}")