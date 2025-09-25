# bruteforce.py
import os
import sys
import random
import traceback
from typing import Dict, Any, Optional
from datetime import datetime

# para que los módulos locales se puedan importar
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from bd import fetch_ip_malas, insert_alert_to_db
from save_csv import append_row_to_csv

try:
    from utils import (
        consultar_abuseipdb_ip,
        consultar_ipqs_ip,
        get_country_for_ip,
        get_network_enrichment,
        score_from_bruteforce,
        clasificar_por_score_final
    )
except Exception:
    consultar_abuseipdb_ip = None
    consultar_ipqs_ip = None
    get_country_for_ip = None
    get_network_enrichment = None
    score_from_bruteforce = None
    clasificar_por_score_final = None

# --- Constantes y Fallbacks ---
ATT_MIN, ATT_MAX, ATT_STEP = 100, 1000, 100
RATE_MIN, RATE_MAX, RATE_STEP = 30, 80, 10
FALLBACK_IP = "89.248.165.72" # IP de fallback si la BD falla

def pick_ip() -> str:
    """
    Intenta leer una IP de la tabla ip_malas. Si falla, usa fallback.
    """
    try:
        ips = fetch_ip_malas()
        if not ips:
            raise RuntimeError("La tabla 'ip_malas' no devolvió IPs.")
        return random.choice(ips)
    except Exception as e:
        print(f"[bruteforce] Aviso: No se pudo leer 'ip_malas' de la BBDD. Usando IP de fallback. Detalle: {e}")
        return FALLBACK_IP


def generate_alert(
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    client_id: Optional[int] = None
) -> Dict[str, Any]:
    """
    Genera una alerta de fuerza bruta y la guarda opcionalmente.
    """
    # ----------------- Generación base -----------------
    ip = pick_ip()
    now = datetime.now()
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    target = random.choice(["ssh", "smb"])
    intentos = random.choice(list(range(ATT_MIN, ATT_MAX + 1, ATT_STEP)))
    ratio = random.choice(list(range(RATE_MIN, RATE_MAX + 1, RATE_STEP)))

    # ----------------- Enriquecimiento -----------------
    abuse_json = ipqs_ip_json = None
    codigo_pais = as_owner = isp = vpn = None
    score_final = 0.0

    if with_enrichment and all([consultar_abuseipdb_ip, get_country_for_ip, get_network_enrichment, score_from_bruteforce]):
        try:
            abuse_json = consultar_abuseipdb_ip(ip)
            ipqs_ip_json = consultar_ipqs_ip(ip)

            codigo_pais = get_country_for_ip(ip, abuse_json=abuse_json)
            net_enrich = get_network_enrichment(ip, vt_json=None, ipqs_json=ipqs_ip_json)
            as_owner = net_enrich.get("as_owner")
            isp = net_enrich.get("isp")
            vpn = net_enrich.get("vpn")

            score_final = score_from_bruteforce(
                abuse_json=abuse_json,
                intentos=intentos,
                ratio=ratio,
                target=target
            )
        except Exception:
            print(f"[bruteforce] Fallo durante el enriquecimiento para la IP {ip}")
            traceback.print_exc()
            
    riesgo_text = clasificar_por_score_final(score_final) if clasificar_por_score_final else "Desconocido"

    # ----------------- Preparación de Datos -----------------
    row_db = {
        "fecha": fecha, "hora": hora, "ip": ip,
        "codigo_pais": codigo_pais,
        "target": target,
        "intentos": intentos,
        "ratio": ratio,
        "as_owner": as_owner,
        "isp": isp,
        "vpn": vpn,
        "abuse_confidence_raw": (abuse_json or {}).get("data", {}).get("abuseConfidenceScore") if isinstance(abuse_json, dict) else None,
        "score_final": score_final,
        "riesgo": riesgo_text,
    }

    if save_csv:
        append_row_to_csv(row_db, attack_type="bruteforce")

    # ----------------- Guardado en BD -----------------
    result_db = None
    if save_db:
        try:
            result_db = insert_alert_to_db(row_db, table_name="alertas_fuerza_bruta", cliente_nombre=client_id)
            if not result_db.get("ok"):
                print(f"[bruteforce] Error guardando en BD: {result_db.get('error')}")
            else:
                print(f"[bruteforce] Insertado en BD con id={result_db.get('id')}")
        except Exception:
            print("[bruteforce] Excepción crítica guardando en BD:")
            traceback.print_exc()

    # ----------------- RETURN ESTANDARIZADO -----------------
    return {
        "ok": True,
        "alerta": row_db,
        "saved": {"csv": save_csv, "db": result_db}
    }


if __name__ == "__main__":
    # Ejemplo de cómo probar el script de forma independiente
    alerta_generada = generate_alert(with_enrichment=True, save_db=False, client_id=1)
    print(alerta_generada)