import csv
import json
import os
from datetime import datetime
from helpers.normalize import convertir_tipo, es_ip
import re

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
            # Normaliza filas incompletas
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
                        # Campos que suenan a fechas
                        if any(x in h.lower() for x in ["date", "fecha", "created", "first", "last"]):
                            valor = convertir_tipo(raw)
                        else:
                            valor = convertir_tipo(raw)

                fila_dict[h] = valor

            datos.append(fila_dict)

        # Guarda JSON
        with open(ruta_json, 'w', encoding='utf-8') as f_json:
            json.dump(datos, f_json, indent=4, ensure_ascii=False, default=str)

        # Borra el CSV original
        try:
            os.remove(ruta_csv)
        except Exception:
            pass

        print(f"[+] JSON guardado en: {ruta_json}")

    except Exception as e:
        print(f"[!] Error al convertir {ruta_csv} a JSON: {e}")
