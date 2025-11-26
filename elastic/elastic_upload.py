import os
import glob
import json
from datetime import datetime
from helpers.normalize import nombre_indice_valido
from elastic.elastic_utils import crear_indice_si_no_existe, subir_documentos_bulk

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