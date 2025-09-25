# ddos.py
import os
import sys
import random
import traceback
from datetime import datetime
from typing import Dict, Any, Optional

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from bd import insert_alert_to_db
from save_csv import append_row_to_csv

try:
    from dos import pick_ip_from_db
except ImportError:
    print("Error: No se pudo importar 'pick_ip_from_db' desde 'dos.py'.")
    def pick_ip_from_db():
        return "141.98.10.60"

try:
    from utils import (
        consultar_abuseipdb_ip,
        consultar_ipqs_ip,
        get_country_for_ip,
        get_network_enrichment,
        score_from_ddos,
        clasificar_por_score_final,
    )
except Exception:
    consultar_abuseipdb_ip = None
    consultar_ipqs_ip = None
    get_country_for_ip = None
    get_network_enrichment = None
    score_from_ddos = None
    clasificar_por_score_final = None

# --- Constantes ---
SRC_MIN, SRC_MAX, SRC_STEP     =   300,   1500, 100
REQ_MIN, REQ_MAX, REQ_STEP     = 10000, 100000, 5000
RATE_MIN, RATE_MAX, RATE_STEP  =   500,   5000, 100

def generate_ddos_alert(
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    client_id: Optional[int] = None
) -> Dict[str, Any]:
    # ----------------- Generación base -----------------
    ip = pick_ip_from_db()
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    # --- LÍNEA CORREGIDA ---
    hora = now.strftime("%H:%M:%S")

    sources = random.choice(list(range(SRC_MIN, SRC_MAX + 1, SRC_STEP)))
    requests_count = random.choice(list(range(REQ_MIN, REQ_MAX + 1, REQ_STEP)))
    ratio = random.choice(list(range(RATE_MIN, RATE_MAX + 1, RATE_STEP)))
    
    # ----------------- Enriquecimiento -----------------
    abuse_json = ipqs_ip_json = None
    codigo_pais = as_owner = isp = vpn = None
    score_final = 0.0

    if with_enrichment and all([consultar_abuseipdb_ip, get_country_for_ip, get_network_enrichment, score_from_ddos]):
        try:
            abuse_json = consultar_abuseipdb_ip(ip)
            ipqs_ip_json = consultar_ipqs_ip(ip)

            codigo_pais = get_country_for_ip(ip, abuse_json=abuse_json)
            net_enrich = get_network_enrichment(ip, vt_json=None, ipqs_json=ipqs_ip_json)
            as_owner = net_enrich.get("as_owner")
            isp = net_enrich.get("isp")
            vpn = net_enrich.get("vpn")

            score_final = score_from_ddos(
                abuse_json=abuse_json,
                sources=sources,
                requests_count=requests_count,
                rate=ratio
            )
        except Exception:
            print(f"[ddos] Fallo durante el enriquecimiento para la IP {ip}")
            traceback.print_exc()

    riesgo_text = clasificar_por_score_final(score_final) if clasificar_por_score_final else "Desconocido"
    
    # ----------------- Preparación de Datos -----------------
    row_db = {
        "fecha": fecha, "hora": hora, "ip": ip,
        "codigo_pais": codigo_pais,
        "sources": sources,
        "requests": requests_count,
        "ratio": ratio,
        "as_owner": as_owner,
        "isp": isp,
        "vpn": vpn,
        "abuse_confidence_raw": (abuse_json or {}).get("data", {}).get("abuseConfidenceScore") if isinstance(abuse_json, dict) else None,
        "score_final": score_final,
        "riesgo": riesgo_text
    }

    if save_csv:
        append_row_to_csv(row_db, attack_type="ddos")

    # ----------------- Guardado en BD -----------------
    result_db = None
    if save_db:
        try:
            result_db = insert_alert_to_db(row_db, table_name="alertas_ddos", cliente_nombre=client_id)
            if not result_db.get("ok"):
                print(f"[ddos] Error guardando en BD: {result_db.get('error')}")
            else:
                print(f"[ddos] Insertado en BD con id={result_db.get('id')}")
        except Exception:
            print("[ddos] Excepción crítica guardando en BD:")
            traceback.print_exc()

    # ----------------- RETURN ESTANDARIZADO -----------------
    return {
        "ok": True,
        "alerta": row_db,
        "saved": {"csv": save_csv, "db": result_db},
    }