 ![Logo](imagenes/Portada.png)

# 🛡️ DEFENDER MONITOR  
**Plataforma de Monitorización y Respuesta a Incidentes de Ciberseguridad (SIRP)**  

Defender Monitor es una solución de **Capgemini** para la detección, gestión y respuesta de alertas de ciberseguridad en tiempo real.  
El sistema centraliza los logs de seguridad, los enriquece con información de múltiples APIs externas y permite visualizar los resultados desde una interfaz web moderna y responsive.  

La plataforma ayuda a las organizaciones a:  
- Centralizar las alertas.  
- Priorizar los incidentes.  
- Reducir los tiempos de detección y respuesta.  
- Facilitar el cumplimiento normativo mediante un registro histórico centralizado.  

---

## ¿QUÉ PUEDES HACER CON DEFENDER MONITOR?

✅ Monitorizar intentos de ataque en tiempo real.  
✅ Generar alertas enriquecidas con datos externos (VirusTotal, OTX, AbuseIPDB…).  
✅ Guardar automáticamente las incidencias en una base de datos relacional (PostgreSQL).  
✅ Descargar informes en **PDF** con métricas y mitigaciones recomendadas.  
✅ Consultar IPs y URLs sospechosas directamente desde la web.  
✅ Filtrar incidentes por gravedad, cliente, tipo de ataque o estado de alerta.  
✅ Visualizar dashboards con **mapa geográfico de ataques, mapa de calor horario y KPIs clave**.  

---

## TECNOLOGÍAS UTILIZADAS 

- **Python 3.10+** — Backend de análisis y clasificación de logs.  
- **FastAPI y Flask** — API principales para la comunicación con frontend y bases de datos.  
- **PostgreSQL (AWS RDS)** — Base de datos en la nube con tablas de clientes, tipos de ataque y alertas.  
- **Docker** — Despliegue y portabilidad del proyecto.  
- **React + Tailwind** — Interfaz web responsive y dinámica.  
- **Pandas / Scikit-learn** — Procesamiento de datos y métricas.  
- **Servicios externos** — VirusTotal, OTX, AbuseIPDB, URL Scan e IPQualityScore para enriquecimiento de alertas.  

---

## ESTRUCTURA DEL PROYECYO

```bash
datascience/
│── bd.py              # Conexión con BBDD y manejo de tablas de alertas
│── main.py            # Generación de alertas y enriquecimiento con APIs
│── utils.py           # Funciones auxiliares (scoring, consultas a APIs, ensamblaje)
│── save_csv.py        # Exportación de alertas a CSV
│── requirements.txt   # Dependencias del proyecto
│── notebooks/         # Jupyter notebooks con pruebas y análisis
│── tests/             # Pruebas unitarias
│── .env               # Variables sensibles (APIs, conexión BBDD)
│── README.md          # Este archivo

```

## MODELO DE BASE DE DATOS
### Diagrama Entidad- Relación
 ![Diagrama ER](imagenes/diagramaentidad.jpg)


 ### Modelo Relacional

 ![Modelo Relacional](imagenes/diagramarelacional.png)


## FLUJO DE FUNCIONAMIENTO

1. **Ingreso del log** → Se recibe un evento sospechoso.  
2. **Clasificación** → Se determina el tipo de ataque (login, phishing, DDoS, fuerza bruta, etc.).  
3. **Enriquecimiento** → Consultas automáticas a APIs externas de threat intelligence.  
4. **Almacenamiento** → Inserción en PostgreSQL y exportación a CSV.  
5. **Visualización** → Dashboards en web con métricas, mapas e informes descargables.  

---

## GRÁFICAS

El sistema genera gráficos para facilitar la interpretación:

- **Distribución de ataques por tipo**  
- **Evolución temporal de incidentes**  
- **Mapa de calor por franjas horarias**  
- **IPs más frecuentes**  
- **Clientes más afectados**

![Graficos1](imagenes/graficosuno.jpg)
![Graficos2](imagenes/graficosdos.jpg)
![Graficos3](imagenes/graficostres.jpg)

---

## BENEFICIOS PARA LA EMPRESA 

✅ **Visibilidad en tiempo real** de intentos de ataque.  
✅ **Reducción del tiempo de respuesta** gracias al triaje automático.  
✅ **Prevención de riesgos** con alertas prioritarias.  
✅ **Optimización de recursos** al identificar picos horarios y regiones más activas.  
✅ **Soporte a auditorías y compliance** con histórico centralizado de incidentes.  

---

## POSIBLES MEJORAS FUTURAS 
  
- [ ] Automatización de respuestas (bloqueo de IPs en tiempo real).  
- [ ] Implementación de un motor de Machine Learning para predicción de ataques.  
- [ ] Ampliar la capa de visualización con gráficas avanzadas en tiempo real.
- [ ] Utilizar LLM para enriquecer respuestas y generar informes más exhaustivos
- [ ] Mejorar la estética del front y la experiencia UX
- [ ] Cabiar estructura de la BBDD a Mongo para mejor escalabilidad
- [ ] Importación de datos mediante CSV

---


## CONFIGURACIÓN DEL ENTORNO LOCAL

Sigue estos pasos para levantar el proyecto en tu máquina.

### 1) Clonar el repositorio
```bash
git clone https://github.com//baldomerothebridge/desafio.git
cd desafio
```

### 2) Crear y activar entorno virtual
```bash
# Crear
python -m venv venv

# Activar en Windows
venv\Scripts\activate

# Activar en macOS/Linux
source venv/bin/activate
```

### 3) Instalar dependencias
```bash
pip install -r requirements.txt
```

### 4) Configurar variables de entorno
Crea un archivo **.env** en la raíz con tus credenciales:

```env
# === Base de datos ===
DB_HOST=TU_HOST_DE_AWS
DB_USER=TU_USUARIO
DB_PASSWORD=TU_CONTRASEÑA
DB_PORT=5432
DB_NAME=defender_monitor

# === Threat Intelligence APIs ===
virustotal_api_key=TU_API_KEY
abuseipdb_api_key=TU_API_KEY
otx_api_key=TU_API_KEY
urlscan_api_key=TU_API_KEY
ipquality_api_key=TU_API_KEY
```

### 5) Ejecutar la aplicación
```bash
python main.py
```

La API (FastAPI) estará disponible en:
- `http://127.0.0.1:5000`  


---

👨‍💻 *Proyecto desarrollado en el marco del **Desafío Fin Bootcamp** por el equipo de Ciberseguridad, Fullstack y Data Science.* 

*Visite el repositorio del equipo de Fullstack*

https://github.com/choski91/Proyecto-final-Tripulaciones-F.S.git
