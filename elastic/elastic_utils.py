import json
import requests
from requests.auth import HTTPBasicAuth
from helpers.normalize import mapping_por_carpeta

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