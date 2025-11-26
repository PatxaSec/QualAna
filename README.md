
<img width="800" height="800" alt="imagen" src="https://github.com/user-attachments/assets/193a752a-fc4b-48e1-89e6-686b6d77a66c" />


# **QualAna – Qualys Analyzer**

**Automatización completa de descarga, normalización y envío de datos de Qualys hacia Elasticsearch**

## 🛡️ Descripción General

**QualAna** es una herramienta desarrollada para automatizar la extracción, normalización, conversión y carga de datos provenientes de múltiples APIs de Qualys.

Una de sus funciones principales es proporcionar historización completa de los datos.
Qualys, por defecto, solo permite consultar la información del último escaneo, lo que dificulta poder realizar análisis temporales, comparar tendencias, o investigar cambios en hosts, vulnerabilidades, inventario o políticas.

Con QualAna, todos los datos descargados quedan almacenados de forma persistente en estructura JSON y, opcionalmente, enviados a Elasticsearch, lo que permite al analista:

- Revisar datos de días anteriores
- Comparar cambios entre escaneos
- Detectar apariciones o desapariciones de vulnerabilidades
- Analizar evolución del inventario de software
- Auditar modificaciones en policies o usuarios

Esto convierte a QualAna en una capa fundamental para disponer de histórico completo cuando la plataforma Qualys por sí sola no lo permite.

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
python3 main.py -c Cliente1
```

#### ✔ Ejecutar para **todos los clientes** definidos:

```bash
python3 main.py -c All
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

---

# 🏗️ **Ejemplo de despliegue local con Docker (Elasticsearch + Kibana)**

Si deseas usar QualAna con Elasticsearch en **localhost**, aquí tienes un ejemplo funcional con Docker.
Donde las credenciales de acceso vía web a kibana son `elastic`:`elastic`

## 📄 `docker-compose.yml`

```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false
      - ELASTIC_PASSWORD=elastic
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data
    networks:
      - elastic

  kibana:
    image: docker.elastic.co/kibana/kibana:8.15.0
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana
      - ELASTICSEARCH_PASSWORD=kibana_passwd
      - SERVER_PUBLICBASEURL=http://localhost:5601
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - elastic

volumes:
  es_data:

networks:
  elastic:
    driver: bridge
```

---

## 🛠️ Crear usuario Kibana en Elasticsearch

Antes de que Kibana pueda autenticarse correctamente, necesitas crear el usuario `kibana` dentro del contenedor de Elasticsearch.

### 1️⃣ Entra en el contenedor:

```bash
docker exec -it elasticsearch bash
```

### 2️⃣ Crea el usuario:

```bash
bin/elasticsearch-users useradd kibana -p kibana_passwd -r kibana_system
```

### 3️⃣ Reinicia los contenedores:

```bash
docker restart elasticsearch kibana
```


