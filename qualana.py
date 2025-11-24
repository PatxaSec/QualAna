#!/usr/bin/env python3
# QualAna: Qualys Analyzer
# Made By: PatxaSec

import requests
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
import base64
import argparse
from datetime import date, datetime
import os
import sys
import csv
import json
import urllib3
import glob
import configparser
import re

csv.field_size_limit(1000000)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

banner = '''
       ___     _   _     _       _         _      _   _       _      
      / " \ U |"|u| |U  /"\  u  |"|    U  /"\  u | \ |"|  U  /"\  u  
     | |"| | \| |\| | \/ _ \/ U | | u   \/ _ \/ <|  \| |>  \/ _ \/   
    /| |_| |\ | |_| | / ___ \  \| |/__  / ___ \ U| |\  |u  / ___ \   
    U \__\_\u<<\___/ /_/   \_\  |_____|/_/   \_\ |_| \_|  /_/   \_\  
       \\// (__) )(   \\    >>  //  \\  \\    >> ||   \\,-.\\    >>  
      (_(__)    (__) (__)  (__)(_")("_)(__)  (__)(_")  (_/(__)  (__) 
    By PatxaSec
'''

# ---------------------
# Helpers de normalización
# ---------------------

def nombre_indice_valido(nombre):
    return nombre.lower().replace("\\", "-").replace("/", "-").replace(" ", "-")

def es_ip(valor):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(valor)))

def es_uuid(valor):
    return bool(re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", str(valor)))

def inferir_tipo_elastic(valor):
    """
    Decide un tipo ELASTIC (string: 'keyword','text','date','ip','boolean','long','float') a partir del valor.
    """
    if valor is None:
        return "keyword"
    if isinstance(valor, bool):
        return "boolean"
    if isinstance(valor, int):
        return "long"
    if isinstance(valor, float):
        return "float"
    if isinstance(valor, (list, tuple)):
        if not valor:
            return "keyword"
        return inferir_tipo_elastic(valor[0])
    s = str(valor).strip()
    if s == "":
        return "keyword"
    # IP
    if es_ip(s):
        return "ip"
    if re.match(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?", s):
        return "date"
    # UUID
    if es_uuid(s):
        return "keyword"
    if re.match(r"^-?\d+$", s):
        return "long"
    if re.match(r"^-?\d+[,\.]\d+$", s):
        return "float"
    if " " in s or len(s) > 50:
        return "text"
    return "keyword"

def mapping_por_carpeta(carpeta, ejemplo_doc):
    propiedades = {}
    carpeta_lower = (carpeta or "").lower()
    if carpeta_lower == "hosts":
        reglas = {"ip": "ip", "id": "keyword", "dns": "keyword", "os": "keyword", "last_scan": "date"}
    elif carpeta_lower == "users":
        reglas = {"login": "keyword", "email": "keyword", "firstname": "text", "lastname": "text", "created": "date"}
    elif carpeta_lower == "vulns":
        reglas = {"qid": "keyword", "ip": "ip", "severity": "long", "title": "text", "first_found": "date"}
    elif carpeta_lower == "policies":
        reglas = {"policy_id": "keyword", "host_id": "keyword", "status": "keyword"}
    elif carpeta_lower == "inventario":
        reglas = {"software": "keyword", "version": "keyword", "publisher": "keyword", "hosts": "keyword"}
    else:
        reglas = {}

    for campo, valor in (ejemplo_doc or {}).items():
        tipo = inferir_tipo_elastic(valor)
        for regla, tipo_fijo in reglas.items():
            if regla in campo.lower():
                tipo = tipo_fijo
                break
        if tipo == "date":
            propiedades[campo] = {"type": "date", "format": "strict_date_optional_time||yyyy-MM-dd||yyyy-MM-dd HH:mm:ss||epoch_millis"}
        else:
            propiedades[campo] = {"type": tipo}
    return {"mappings": {"properties": propiedades}} if propiedades else {}

# ---------------------
# Conversión / parser CSV
# ---------------------

def convertir_tipo(valor):
    """
    Convierte un string a int/float/bool/date(iso) o devuelve string.
    Siempre devuelve tipos serializables JSON: no devuelve objetos datetime, devuelve strings ISO.
    """
    if valor is None:
        return None
    v = str(valor).strip()
    if v == "":
        return None
    if v.lower() in ("true", "false", "yes", "no", "y", "n"):
        return v.lower() in ("true", "yes", "y")
    if re.match(r"^-?\d+$", v):
        try:
            return int(v)
        except Exception:
            pass
    if re.match(r"^-?\d+[,\.]\d+$", v):
        v2 = v.replace(",", ".")
        try:
            return float(v2)
        except Exception:
            pass
    formatos_fecha = ["%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d", "%Y-%m-%d %H:%M:%S",
                      "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]
    for fmt in formatos_fecha:
        try:
            dt = datetime.strptime(v, fmt)
            return dt.isoformat()
        except Exception:
            continue
    if es_ip(v):
        return v
    return v

def csv_a_json(ruta_csv, ruta_json):
    try:
        with open(ruta_csv, 'r', encoding='utf-8-sig', newline='') as f_csv:
            reader = csv.reader(f_csv)
            filas = list(reader)
        if not filas:
            raise ValueError("CSV vacío")
        encabezados = [h.strip().replace('\ufeff', '') for h in filas[0]]
        datos = []
        for fila in filas[1:]:
            if len(fila) < len(encabezados):
                fila = fila + [''] * (len(encabezados) - len(fila))
            fila_dict = {}
            for h, v in zip(encabezados, fila):
                if v is None:
                    valor = None
                else:
                    raw = v.strip()
                    if raw in ("", "N/A", "NA", "None", "-"):
                        valor = None
                    else:
                        if any(x in h.lower() for x in ["date", "fecha", "created", "first", "last"]):
                            parsed = convertir_tipo(raw)
                            valor = parsed
                        else:
                            valor = convertir_tipo(raw)
                fila_dict[h] = valor
            datos.append(fila_dict)
        with open(ruta_json, 'w', encoding='utf-8') as f_json:
            json.dump(datos, f_json, indent=4, ensure_ascii=False, default=str)
        try:
            os.remove(ruta_csv)
        except Exception:
            pass
        print(f"[+] JSON guardado en: {ruta_json}")
    except Exception as e:
        print(f"[!] Error al convertir {ruta_csv} a JSON: {e}")

# ---------------------
# Elasticsearch: creación de indice + subida bulk
# ---------------------

def crear_indice_si_no_existe(nombre_indice, elastic_url, elastic_user, elastic_pass, carpeta=None, ejemplo_doc=None):
    url = f"http://{elastic_url}/{nombre_indice}"
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.head(url, auth=HTTPBasicAuth(elastic_user, elastic_pass))
    except Exception as e:
        print(f"[!] Error conectando a Elasticsearch: {e}")
        return
    if response.status_code == 200:
        print(f"[i] Índice ya existe: {nombre_indice}")
        return
    mapping = {}
    if ejemplo_doc:
        mapping = mapping_por_carpeta(carpeta, ejemplo_doc)
    try:
        response = requests.put(url, headers=headers, auth=HTTPBasicAuth(elastic_user, elastic_pass), data=json.dumps(mapping) if mapping else None)
        if response.status_code in (200, 201):
            print(f"[+] Índice creado: {nombre_indice}")
        else:
            print(f"[!] Error al crear índice {nombre_indice}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[!] Excepción al crear índice {nombre_indice}: {e}")

def subir_documentos_bulk(elastic_url, indice, documentos, user, passwd):
    bulk_lines = []
    for doc in documentos:
        bulk_lines.append(json.dumps({"index": {}}))
        bulk_lines.append(json.dumps(doc, ensure_ascii=False, default=str))
    bulk_data = "\n".join(bulk_lines) + "\n"
    try:
        r = requests.post(f"http://{elastic_url}/{indice}/_bulk", headers={"Content-Type": "application/x-ndjson"}, data=bulk_data.encode('utf-8'), auth=HTTPBasicAuth(user, passwd))
    except Exception as e:
        print(f"[!] Error enviando bulk: {e}")
        return False
    if r.status_code >= 300:
        print(f"[!] Error en subida bulk: {r.status_code}")
        print(r.text)
        return False
    try:
        result = r.json()
    except Exception:
        print("[!] Respuesta no JSON de Elasticsearch en bulk.")
        return False
    errores = [item for item in result.get("items", []) if item.get("index", {}).get("error")]
    if errores:
        print(f"[!] {len(errores)} errores al insertar.")
        print(json.dumps(errores[:5], indent=2))
        return False
    print(f"[+] Subida exitosa. Insertados: {len(documentos)}")
    return True

# ---------------------
# Funciones Qualys / procesos (sin cambios lógicos importantes)
# ---------------------

def postura(user, passwd, cliente, policy_ids):
    if not policy_ids:
        print("[i] No hay policy_ids, se omite postura()")
        return
    headers={'X-Requested-With':'curl'}
    url='https://qualysguard.qg2.apps.qualys.eu/api/2.0/fo/compliance/posture/info/'
    ruta_directorio=os.path.join("Clientes",cliente,"Policies")
    os.makedirs(ruta_directorio,exist_ok=True)
    for policy_id in policy_ids:
        print(f"[*] Descargando datos para policy_id {policy_id}...")
        params={'action':'list','policy_id':str(policy_id),'output_format':'csv_no_metadata'}
        try:
            response=requests.get(url,headers=headers,params=params,auth=(user,passwd),verify=False)
            if response.status_code!=200:
                raise Exception(f"Error al descargar postura (HTTP {response.status_code})")
            nombre_base=f"{cliente}_policy_{policy_id}_{date.today().isoformat()}"
            ruta_csv=os.path.join(ruta_directorio,f"{nombre_base}.csv")
            ruta_json=os.path.join(ruta_directorio,f"{nombre_base}.json")
            with open(ruta_csv,'wb') as archivo:
                archivo.write(response.content)
            print(f"[*] Datos descargados para policy_id {policy_id}: {ruta_csv}")
            csv_a_json(ruta_csv,ruta_json)
            print(f"[*] Convertido a JSON: {ruta_json}")
        except Exception as e:
            print(f"[!] Error al procesar policy_id {policy_id}: {e}")
    print("[+] Proceso completado para todas las policies.")

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

# ---------------------
# Subida a Elasticsearch (por carpeta)
# ---------------------

def subir_a_elasticsearch(cliente, elastic_url, elastic_user, elastic_passwd):
    base_dir = os.path.join("Clientes", cliente)
    if not os.path.exists(base_dir):
        print(f"[!] No existe la carpeta {base_dir}")
        return
    subcarpetas = ["Hosts", "Users", "Vulns", "Policies", "Inventario"]
    for sub in subcarpetas:
        carpeta = os.path.join(base_dir, sub)
        if not os.path.exists(carpeta):
            continue
        json_files = glob.glob(os.path.join(carpeta, "*.json"))
        if not json_files:
            continue
        print(f"[*] Subiendo {len(json_files)} archivos de {sub} a Elasticsearch...")
        indice = nombre_indice_valido(f"{cliente}-{sub}")
        ejemplo_doc = None
        try:
            with open(json_files[0], "r", encoding="utf-8") as f:
                datos_ejemplo = json.load(f)
                if isinstance(datos_ejemplo, list) and len(datos_ejemplo) > 0:
                    ejemplo_doc = datos_ejemplo[0]
        except Exception:
            pass
        crear_indice_si_no_existe(indice, elastic_url, elastic_user, elastic_passwd, sub, ejemplo_doc)
        for file in json_files:
            try:
                with open(file, "r", encoding="utf-8") as f:
                    datos = json.load(f)
                if not isinstance(datos, list) or not datos:
                    print(f"[i] Archivo vacío o formato inesperado, se salta: {file}")
                    continue
                for d in datos:
                    for k, v in list(d.items()):
                        if isinstance(v, datetime):
                            d[k] = v.isoformat()
                ok = subir_documentos_bulk(elastic_url, indice, datos, elastic_user, elastic_passwd)
                if ok:
                    if file.lower().endswith(".json"):
                        nuevo = file[:-5] + ".json.bak"
                    else:
                        nuevo = file + ".json.bak"
                    try:
                        os.replace(file, nuevo)
                        print(f"[+] Archivo renombrado: {file} -> {nuevo}")
                    except Exception as e:
                        print(f"[!] No se pudo renombrar {file} -> {nuevo}: {e}")
                else:
                    print(f"[!] No se renombró {file} porque la subida falló.")
            except Exception as e:
                print(f"[!] Error procesando {file}: {e}")

# ---------------------
# CLI y ejecución
# ---------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automatiza la descarga de datos de Qualys por cliente.')
    parser.add_argument('-c', '--cliente', required=True, help='Nombre del cliente definido en qualys_cliente.conf o "All" para ejecutar todos.')
    parser.add_argument('--conf', default='qualys_cliente.conf', help='Archivo de configuración')
    args = parser.parse_args()
    config = configparser.ConfigParser()
    print(banner)
    if not config.read(args.conf):
        print(f"[X] No se pudo leer {args.conf}")
        sys.exit(1)
    clientes = config.sections() if args.cliente == "All" else [args.cliente]
    for cliente in clientes:
        if cliente not in config:
            print(f"[X] Cliente {cliente} no encontrado en {args.conf}")
            continue
        sec = config[cliente]
        user = sec.get('usuario')
        passwd = sec.get('password')
        policy_ids = [int(x.strip()) for x in sec.get('policy_ids', '').split(',') if x.strip().isdigit()]
        elastic_url = sec.get('elastic_url')
        elastic_user = sec.get('elastic_user', fallback=user)
        elastic_passwd = sec.get('elastic_passwd', fallback=passwd)
        if sec.getboolean('hosts', fallback=False):
            host_list(user, passwd, cliente)
        if sec.getboolean('users', fallback=False):
            qualys_users_list(user, passwd, cliente)
        if sec.getboolean('vulnerabilities', fallback=False) or sec.getboolean('vulnerabilidades', fallback=False):
            vulnerabilidades(base64.b64encode(f"{user}:{passwd}".encode()).decode(), cliente)
        if sec.getboolean('inventario', fallback=False):
            inventario(user, passwd, cliente)
        if policy_ids:
            postura(user, passwd, cliente, policy_ids)
        if sec.getboolean('elastic', fallback=False):
            if elastic_url:
                subir_a_elasticsearch(cliente, elastic_url, elastic_user, elastic_passwd)
            else:
                print(f"[!] {cliente}: elastic=true pero falta elastic_url")
    print("[+] Ejecución finalizada.")

