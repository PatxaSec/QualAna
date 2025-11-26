#!/usr/bin/env python3
# QualAna: Qualys Analyzer
# Made By: PatxaSec

import argparse
import configparser
import sys
import base64
from utils.banner import banner
from qualys.hosts import host_list
from qualys.users import qualys_users_list
from qualys.vulnerabilities import vulnerabilidades
from qualys.inventory import inventario
from qualys.posture import postura
from elastic.elastic_upload import subir_a_elasticsearch

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automatiza la descarga de datos de Qualys por cliente.')
    parser.add_argument('-c', '--cliente', required=True, help='Cliente definido en qualys_cliente.conf o "All"')
    parser.add_argument('--conf', default='qualys_cliente.conf', help='Archivo de configuración')
    args = parser.parse_args()

    print(banner)

    config = configparser.ConfigParser()
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
        elastic_url   = sec.get('elastic_url')
        elastic_user  = sec.get('elastic_user', fallback=user)
        elastic_pass  = sec.get('elastic_passwd', fallback=passwd)
        policy_ids = [int(x.strip()) for x in sec.get('policy_ids', '').split(',') if x.strip().isdigit()]

        if sec.getboolean('hosts', False):
            host_list(user, passwd, cliente)

        if sec.getboolean('users', False):
            qualys_users_list(user, passwd, cliente)

        if sec.getboolean('vulnerabilities', False) or sec.getboolean('vulnerabilidades', False):
            auth = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            vulnerabilidades(auth, cliente)

        if sec.getboolean('inventario', False):
            inventario(user, passwd, cliente)

        if policy_ids:
            postura(user, passwd, cliente, policy_ids)

        if sec.getboolean('elastic', False):
            if elastic_url:
                subir_a_elasticsearch(cliente, elastic_url, elastic_user, elastic_pass)
            else:
                print(f"[!] {cliente}: elastic=true pero falta elastic_url")

    print("[+] Ejecución finalizada.")
