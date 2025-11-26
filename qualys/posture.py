import requests
import os
from datetime import date
from helpers.csv_parser import csv_a_json

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