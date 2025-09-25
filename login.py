# login.py
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
        consultar_virustotal_ip,
        consultar_abuseipdb_ip,
        consultar_otx_ip,
        crear_alerta_final,
    )
except Exception:
    consultar_virustotal_ip = None
    consultar_abuseipdb_ip = None
    consultar_otx_ip = None
    crear_alerta_final = None

# --- Datos de demo y fallbacks ---
USUARIOS_DEMO = ["admin", "root", "test", "guest", "operador", "soporte"]
SERVICIOS_DEMO = ["ssh", "web", "vpn", "smb"]
FALLBACK_BAD_IPS = ["45.155.205.233", "185.220.101.1", "89.248.165.72", "5.188.206.130", "141.98.10.60"]

def _fallback_ip() -> str:
    return random.choice(FALLBACK_BAD_IPS)

def _pick_ip_from_db() -> str:
    """Intenta leer una IP de la tabla ip_malas. Si falla, usa fallback."""
    try:
        ips = fetch_ip_malas()
        if not ips:
            raise RuntimeError("La tabla 'ip_malas' no devolvió IPs.")
        return random.choice(ips)
    except Exception as e:
        print(f"[login] Aviso: No se pudo leer 'ip_malas' de la BBDD. Usando IP de fallback. Detalle: {e}")
        return _fallback_ip()


def generate_alert(
    with_enrichment: bool = True,
    save_csv: bool = True,
    save_db: bool = True,
    client_id: Optional[int] = None
) -> Dict[str, Any]:
    # ----------------- Generación base -----------------
    ip = _pick_ip_from_db()
    usuario = random.choice(USUARIOS_DEMO)
    servicio = random.choice(SERVICIOS_DEMO)
    intentos = random.randint(3, 20)
    duracion = random.randint(1, 600)
    ratio_intentos = round(intentos / max(1, duracion), 4)

    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    fecha = now.strftime("%Y-%m-%d")
    hora = now.strftime("%H:%M:%S")

    alerta_base = {
        "timestamp": timestamp,
        "usuario": usuario,
        "intentos": intentos,
        "duracion": duracion,
        "ip": ip,
        "login": servicio,
        "uso": "aut"
    }

    # ----------------- Enriquecimiento -----------------
    vt_json = abuse_json = otx_json = None
    if with_enrichment:
        try:
            if consultar_virustotal_ip: vt_json = consultar_virustotal_ip(ip)
        except Exception: traceback.print_exc()
        try:
            if consultar_abuseipdb_ip: abuse_json = consultar_abuseipdb_ip(ip)
        except Exception: traceback.print_exc()
        try:
            if consultar_otx_ip: otx_json = consultar_otx_ip(ip)
        except Exception: traceback.print_exc()

    if crear_alerta_final:
        alerta_final = crear_alerta_final(alerta_base, vt_json=vt_json, abuse_json=abuse_json, otx_json=otx_json)
    else:
        alerta_final = dict(alerta_base) # Fallback si 'utils' no carga

    # ----------------- CSV -----------------
    if save_csv:
        try:
            # Reconstruimos la fila para el CSV a partir de la alerta final enriquecida
            csv_row = alerta_final.copy()
            csv_row["riesgo"] = csv_row.pop("risk_level", None)
            append_row_to_csv(csv_row, attack_type="login")
        except Exception:
            print("[login] Error guardando CSV:")
            traceback.print_exc()

    # ----------------- BD -----------------
    result_db = None
    if save_db:
        try:
            # Para la BD, usamos directamente los campos de la alerta final
            row_db = {
                "fecha": fecha,
                "hora": hora,
                "usuario": usuario,
                "intentos": intentos,
                "duracion": duracion,
                "ratio_intentos": ratio_intentos,
                "ip": ip,
                "login": servicio,
                "pais": alerta_final.get("pais"),
                "isp": alerta_final.get("isp"),
                "uso": alerta_final.get("uso"),
                "resultado_vt_raw": alerta_final.get("resultado_vt_raw"),
                "score_vt": alerta_final.get("score_vt"),
                "score_abuse": alerta_final.get("score_abuse"),
                "score_otx": alerta_final.get("score_otx"),
                "score_final": alerta_final.get("score_final"),
                "riesgo": alerta_final.get("risk_level"),
            }
            result_db = insert_alert_to_db(row_db, table_name="alertas_login_sospechoso", cliente_nombre=client_id)
            if not result_db.get("ok"):
                print(f"[login] Error guardando en BD: {result_db.get('error')}")
            else:
                print(f"[login] Insertado en BD con id={result_db.get('id')}")
        except Exception:
            print("[login] Excepción crítica guardando en BD:")
            traceback.print_exc()

    # ----------------- RETURN ESTANDARIZADO -----------------
    # La alerta para la UI es la 'alerta_final' enriquecida
    alerta_ui = dict(alerta_final)
    alerta_ui.update({"fecha": fecha, "hora": hora})

    return {
        "ok": True,
        "alerta": alerta_ui,
        "saved": {"csv": save_csv, "db": result_db}
    }


if __name__ == "__main__":
    # Ejemplo de cómo probar el script de forma independiente
    alerta_generada = generate_alert(with_enrichment=True, save_db=False, client_id=1)
    print(alerta_generada)