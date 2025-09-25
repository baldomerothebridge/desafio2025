# dos.py
import os
import sys
import random
import traceback
from datetime import datetime
from typing import Dict, Any, Optional

# Asegura que los módulos locales se puedan importar
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from bd import insert_alert_to_db, fetch_ip_malas
from save_csv import append_row_to_csv

try:
    from utils import (
        consultar_abuseipdb_ip,
        consultar_ipqs_ip,
        get_country_for_ip,
        get_network_enrichment,
        score_from_dos,
        clasificar_por_score_final,
    )
except Exception:
    # Si 'utils' falla, se asignan valores nulos para evitar que el script se detenga
    consultar_abuseipdb_ip = None
    consultar_ipqs_ip = None
    get_country_for_ip = None
    get_network_enrichment = None
    score_from_dos = None
    clasificar_por_score_final = None

# --- Constantes y Fallbacks ---
REQ_MIN, REQ_MAX, REQ_STEP   = 1000, 5000, 1000
RATE_MIN, RATE_MAX, RATE_STEP =  100, 1000, 100
FALLBACK_IP = "185.220.101.1" # IP de fallback si la BD falla

def pick_ip_from_db() -> str:
    """
    Intenta leer una IP de la tabla ip_malas. Si falla, usa fallback.
    """
    try:
        ips = fetch_ip_malas()
        if not ips:
            raise RuntimeError("La tabla 'ip_malas' no devolvió IPs.")
        return random.choice(ips)
    except Exception as e:
        print(f"[dos] Aviso: No se pudo leer 'ip_malas' de la BBDD. Usando IP de fallback. Detalle: {e}")
        return FALLBACK_IP

def generate_dos_alert(
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    client_id: Optional[int] = None
) -> Dict[str, Any]:
    """
    Genera una alerta DoS y la guarda opcionalmente en CSV y DB.
    """
    # ----------------- Generación base -----------------
    ip = pick_ip_from_db()
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    requests_count = random.choice(list(range(REQ_MIN, REQ_MAX + 1, REQ_STEP)))
    ratio = random.choice(list(range(RATE_MIN, RATE_MAX + 1, RATE_STEP)))

    # ----------------- Enriquecimiento -----------------
    abuse_json = ipqs_ip_json = None
    codigo_pais = as_owner = isp = vpn = None
    score_final = 0.0

    if with_enrichment and all([consultar_abuseipdb_ip, get_country_for_ip, get_network_enrichment, score_from_dos]):
        try:
            abuse_json = consultar_abuseipdb_ip(ip)
            ipqs_ip_json = consultar_ipqs_ip(ip)

            codigo_pais = get_country_for_ip(ip, abuse_json=abuse_json)
            net_enrich = get_network_enrichment(ip, vt_json=None, ipqs_json=ipqs_ip_json)
            as_owner = net_enrich.get("as_owner")
            isp = net_enrich.get("isp")
            vpn = net_enrich.get("vpn")
            
            score_final = score_from_dos(
                abuse_json=abuse_json,
                requests_count=requests_count,
                rate=ratio
            )
        except Exception:
            print(f"[dos] Fallo durante el enriquecimiento para la IP {ip}")
            traceback.print_exc()
    
    riesgo_text = clasificar_por_score_final(score_final) if clasificar_por_score_final else "Desconocido"
    
    # ----------------- Preparación de Datos -----------------
    row_db = {
        "fecha": fecha, "hora": hora, "ip": ip,
        "codigo_pais": codigo_pais,
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
        append_row_to_csv(row_db, attack_type="dos")

    # ----------------- Guardado en BD -----------------
    result_db = None
    if save_db:
        try:
            result_db = insert_alert_to_db(row_db, table_name="alertas_dos", cliente_nombre=client_id)
            if not result_db.get("ok"):
                print(f"[dos] Error guardando en BD: {result_db.get('error')}")
            else:
                print(f"[dos] Insertado en BD con id={result_db.get('id')}")
        except Exception:
            print("[dos] Excepción crítica guardando en BD:")
            traceback.print_exc()

    # ----------------- RETURN ESTANDARIZADO -----------------
    return {
        "ok": True,
        "alerta": row_db,
        "saved": {"csv": save_csv, "db": result_db},
    }