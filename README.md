# **QualAna – Qualys Analyzer**

**Automatización completa de descarga, normalización y envío de datos de Qualys hacia Elasticsearch**

## 🛡️ Descripción General

**QualAna** es una herramienta desarrollada por **PatxaSec** para automatizar la extracción, normalización, conversión y carga de datos provenientes de múltiples APIs de **Qualys**.

El script descarga de forma automática información de:

* 🖥️ **Hosts**
* 👤 **Usuarios**
* 🛑 **Vulnerabilidades**
* 📜 **Policies / Posture**
* 📦 **Inventario de software (Qualys AM)**

Además, convierte los datos de **CSV → JSON**, aplica normalización de tipos, crea índices en **Elasticsearch** con *mappings inteligentes* y sube los documentos mediante operaciones **bulk**.

---

## ✨ Características Principales

### 🔹 Extracción desde APIs Qualys (VMDR, AM, Compliance)

El script integra varios endpoints de Qualys:

* Host list (XML)
* Users list (XML)
* Vulnerability detections (CSV)
* Posture / Compliance policies (CSV)
* Asset Inventory (JWT REST API)

### 🔹 Conversión + Normalización automática

* Detección automática de **tipos**:
  `ip`, `date`, `long`, `float`, `boolean`, `text`, `keyword`
* Corrección y saneo de campos vacíos
* Conversión de fechas a ISO 8601
* Limpieza de CSVs corruptos o con BOM

### 🔹 Exportación ordenada por cliente

La estructura generada es:

```
Clientes/
 └── Cliente1/
      ├── Hosts/
      ├── Users/
      ├── Vulns/
      ├── Policies/
      └── Inventario/
```

### 🔹 Subida automática a Elasticsearch

* Crea índices si no existen
* Genera mappings específicos por carpeta
* Inserta usando **bulk insert**
* Renombra archivos ya importados → `*.json.bak`

---

## 🚀 Uso

### 1. Configura el archivo `qualys_cliente.conf`

Un ejemplo básico:

[cualys_cliente.conf](./qualys_cliente.conf)

Puedes añadir tantos clientes como desees.

---

### 2. Ejecuta el script

#### ✔ Ejecutar para un solo cliente:

```bash
python3 qualana.py -c Cliente1
```

#### ✔ Ejecutar para **todos los clientes** definidos:

```bash
python3 qualana.py -c All
```

---

## 📦 Dependencias

El script usa:

* Python 3.x
* `requests`
* `urllib3`
* `xml.etree.ElementTree`
* `csv`, `json`
* `argparse`
* `configparser`

Instalación rápida:

```bash
pip3 install requests urllib3
```

---

## 📁 Estructura interna del proyecto

```
qualys_cliente.conf     # Archivo de configuración principal
qualana.py              # Script principal
Clientes/               # Salida organizada por cliente
```

---

## 🧠 Lógica principal del flujo

1. Leer configuración del cliente
2. Consultar las APIs activadas (`hosts`, `users`, `vulnerabilities`, etc.)
3. Descargar los datos
4. Convertir CSV → JSON
5. Inferir tipos y normalizar
6. Crear índices en Elasticsearch
7. Subir datos vía bulk
8. Renombrar archivos procesados

---

## 🛑 Notas importantes

* Se recomienda ejecutar en entorno con **Python 3.9+**
* La API de inventario usa autenticación **JWT**, por lo que requiere conectividad hacia `gateway.qg2.apps.qualys.eu`
* El script ignora advertencias SSL (`verify=False`) por diseño

