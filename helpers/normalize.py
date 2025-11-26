import re
from datetime import datetime

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