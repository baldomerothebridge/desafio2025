# phishing.py
"""
Genera alertas de phishing tomando la URL desde la tabla 'url_malas'.
Calcula score con VT/IPQS y guarda en CSV y BD (alertas_phishing).
"""

import os
import sys
import random
import traceback
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from datetime import datetime

# Asegura que los módulos locales se puedan importar
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from bd import insert_alert_to_db, fetch_url_malas
from save_csv import append_row_to_csv

try:
    from utils import consultar_virustotal_domain, consultar_ipqs_url, score_phishing_url
except Exception:
    consultar_virustotal_domain = None
    consultar_ipqs_url = None
    score_phishing_url = None


def _pick_url_from_db() -> str:
    """Obtiene una URL aleatoria de la tabla url_malas."""
    urls = fetch_url_malas()
    if not urls:
        raise RuntimeError("No hay URLs en la tabla 'url_malas'.")
    return random.choice(urls)


def generate_alert(
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    client_id: Optional[int] = None
) -> Dict[str, Any]:
    # ----------------- Selección URL desde BBDD (con fallback) -----------------
    try:
        url_a_analizar = _pick_url_from_db()
    except Exception as e:
        print(f"[phishing] Aviso: No se pudo leer 'url_malas' de la BBDD. Usando URL de fallback. Detalle: {e}")
        url_a_analizar = "http://example-malicious-site.com/login-phish"

    hostname = urlparse(url_a_analizar).hostname or url_a_analizar

    # ----------------- Enriquecimiento -----------------
    vt_json = ipqs_json = None
    if with_enrichment:
        try:
            if consultar_virustotal_domain:
                vt_json = consultar_virustotal_domain(hostname)
        except Exception:
            traceback.print_exc()
        try:
            if consultar_ipqs_url:
                ipqs_json = consultar_ipqs_url(url_a_analizar)
        except Exception:
            traceback.print_exc()

    # ----------------- Scoring -----------------
    if score_phishing_url:
        score_final = score_phishing_url(vt_json, ipqs_json)
    else:
        score_final = 0.0 # Fallback si la función de scoring no está disponible
    
    # Clasificación del riesgo basada en el score
    if score_final >= 9.0:
        risk_level = "Crítico"
    elif score_final >= 7.0:
        risk_level = "Alto"
    elif score_final >= 4.0:
        risk_level = "Medio"
    elif score_final > 0:
        risk_level = "Bajo"
    else:
        risk_level = "Inofensivo"

    # Resumen corto para la columna 'riesgo'
    vt_malicious = "N/A"
    ipqs_score = "N/A"
    try:
        if isinstance(vt_json, dict) and "data" in vt_json:
            vt_malicious = vt_json["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", "N/A")
    except Exception: pass
    try:
        if isinstance(ipqs_json, dict):
            ipqs_score = ipqs_json.get("risk_score", "N/A")
    except Exception: pass
    resumen_vt_ipqs = f"VT: M{vt_malicious}, IPQS: S{ipqs_score}"

    now = datetime.now()
    fecha = now.strftime('%Y-%m-%d')
    hora = now.strftime('%H:%M:%S')

    # ----------------- Preparación de Datos -----------------
    alerta_para_csv = {
        "fecha": fecha,
        "hora": hora,
        "ip": hostname,
        "url": url_a_analizar,
        "score_final": score_final,
        "risk_level": risk_level,
        "riesgo": resumen_vt_ipqs,
    }

    if save_csv:
        try:
            append_row_to_csv(alerta_para_csv, attack_type="phishing")
        except Exception:
            print("[phishing] Error guardando CSV:")
            traceback.print_exc()

    # ----------------- Guardado en BD -----------------
    result_db = None
    if save_db:
        try:
            # Usamos el mismo diccionario para la BD
            row_db = alerta_para_csv.copy()
            
            result_db = insert_alert_to_db(row_db, table_name="alertas_phishing", cliente_nombre=client_id)
            
            if not result_db.get("ok"):
                print(f"[phishing] Error guardando en BD: {result_db.get('error')}")
            else:
                print(f"[phishing] Insertado en BD con id={result_db.get('id')}")
        except Exception:
            print("[phishing] Excepción crítica guardando en BD:")
            traceback.print_exc()

    # ----------------- RETURN ESTANDARIZADO -----------------
    return {
        "ok": True,
        "alerta": alerta_para_csv,
        "saved": {"csv": save_csv, "db": result_db}
    }


if __name__ == "__main__":
    # Ejemplo de cómo probar el script de forma independiente
    alerta_generada = generate_alert(with_enrichment=True, save_csv=False, save_db=False, client_id=1)
    print(alerta_generada)