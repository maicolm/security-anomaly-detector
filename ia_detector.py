#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ia_detector.py — Detector ligero de anomalías de accesos (por IP)

- Ventana por defecto: últimas 24 horas (configurable por env)
- Features por IP: total_attempts, fail_count, success_count, fail_ratio, users_count
- Modelo: IsolationForest (con fallback a regla si la muestra es pequeña)
- Inserta alertas en security_alerts (label="iforest_ip")
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
import mysql.connector as mysql


# ---------- Config (.env junto a este archivo) ----------
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")  # lee DB_HOST, DB_NAME, DB_USER, DB_PASS, DB_PORT, etc.

DB_CONFIG = dict(
    host=os.getenv("DB_HOST", "127.0.0.1"),
    database=os.getenv("DB_NAME", "demo_app"),
    user=os.getenv("DB_USER", "svc_ia_readonly"),
    password=os.getenv("DB_PASS", ""),
    port=int(os.getenv("DB_PORT", "3306")),
    autocommit=True,
)

WINDOW_HOURS = int(os.getenv("WINDOW_HOURS", "24"))
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

IFOREST_PARAMS = dict(
    n_estimators=200,
    contamination="auto",
    random_state=42,
)


# ---------- Helpers de conexión ----------
def get_conn():
    return mysql.connect(**DB_CONFIG)


# ---------- Extracción ----------
def fetch_login_attempts_since(cutoff_utc: datetime) -> pd.DataFrame:
    """
    Lee los intentos de login desde cutoff_utc (UTC).
    """
    q = """
        SELECT username, ip, user_agent, success, reason, created_at
        FROM login_attempts
        WHERE created_at >= %s
    """
    # Formateo explícito por si la columna es TIMESTAMP sin TZ
    cutoff_str = cutoff_utc.strftime("%Y-%m-%d %H:%M:%S")
    with get_conn() as conn:
        df = pd.read_sql(q, conn, params=[cutoff_str])
    return df


# ---------- Ingeniería de características ----------
def build_features_by_ip(df: pd.DataFrame) -> pd.DataFrame:
    """
    Agrega por IP:
      - total_attempts
      - fail_count
      - success_count
      - fail_ratio
      - users_count
    """
    if df.empty:
        return pd.DataFrame(columns=["ip", "total_attempts", "fail_count", "success_count", "fail_ratio", "users_count"])

    # total por IP
    total = df.groupby("ip", dropna=False).size().rename("total_attempts")

    # conteos de éxito y fallo (sin .apply para evitar warnings)
    fail = (
        df.assign(_fail=(df["success"].astype(int) == 0).astype(int))
          .groupby("ip", dropna=False)["_fail"].sum()
          .rename("fail_count")
    )
    ok = (
        df.assign(_ok=(df["success"].astype(int) == 1).astype(int))
          .groupby("ip", dropna=False)["_ok"].sum()
          .rename("success_count")
    )

    users = df.groupby("ip", dropna=False)["username"].nunique().rename("users_count")

    feat = pd.concat([total, fail, ok, users], axis=1)
    feat["fail_ratio"] = (feat["fail_count"] / feat["total_attempts"]).fillna(0.0)

    feat = feat.reset_index()  # deja 'ip' como columna
    feat = feat[["ip", "total_attempts", "fail_count", "success_count", "fail_ratio", "users_count"]]
    feat = feat.sort_values(["fail_ratio", "fail_count", "total_attempts"], ascending=False, kind="stable")
    return feat


# ---------- Scoring / Detección ----------
def minmax_0_100(values: np.ndarray) -> np.ndarray:
    """
    Reescala a [0, 100]. Si no hay rango, devuelve 50.
    """
    vmin, vmax = float(np.min(values)), float(np.max(values))
    if vmax <= vmin:
        return np.full_like(values, 50.0, dtype=float)
    return 100.0 * (values - vmin) / (vmax - vmin)


def detect_anomalies(feat: pd.DataFrame) -> pd.DataFrame:
    """
    Si hay >=3 IPs: IsolationForest
    Si hay < 3 IPs: regla de respaldo (fail_ratio >= 0.60 y fail_count >= 3)
    Devuelve feat con columna 'score' y flag 'is_anomaly' (bool).
    """
    if feat.empty:
        feat = feat.copy()
        feat["score"] = []
        feat["is_anomaly"] = []
        return feat

    feat = feat.copy()

    if len(feat) >= 3:
        X = feat[["fail_ratio", "fail_count", "total_attempts", "users_count"]].to_numpy(dtype=float)
        model = IsolationForest(**IFOREST_PARAMS)
        yhat = model.fit_predict(X)  # -1 anomalía, 1 normal
        # mayor score => más anómalo (negamos decision_function)
        raw = -model.decision_function(X)
        feat["score"] = np.round(minmax_0_100(raw), 1)
        feat["is_anomaly"] = (yhat == -1)
    else:
        # Fallback: regla simple
        feat["score"] = np.round(feat["fail_ratio"] * 100.0, 1)
        feat["is_anomaly"] = (feat["fail_ratio"] >= 0.60) & (feat["fail_count"] >= 3)

    return feat


# ---------- Inserción de alertas ----------
def insert_alert(username: str | None, ip: str, risk: float, label: str, extra_dict: dict) -> None:
    """
    Inserta una fila en security_alerts.
    """
    payload = json.dumps(extra_dict, ensure_ascii=False)
    sql = """
        INSERT INTO security_alerts (username, ip, risk_score, label, extra)
        VALUES (%s, %s, %s, %s, %s)
    """
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql, (username, ip, float(risk), label, payload))
        conn.commit()


# ---------- MAIN ----------
def main() -> None:
    now_utc = datetime.now(timezone.utc)
    cutoff_utc = now_utc - timedelta(hours=WINDOW_HOURS)
    print(f"[INFO] Ventana: últimas {WINDOW_HOURS}h desde {cutoff_utc:%Y-%m-%d %H:%M:%S} (UTC)")

    df = fetch_login_attempts_since(cutoff_utc)
    print(f"[INFO] Intentos recuperados: {len(df)}")

    feat = build_features_by_ip(df)
    if feat.empty:
        print("\n[INFO] No hay actividad en la ventana.")
        return

    scored = detect_anomalies(feat)

    # Muestra top por ratio de fallos (con score)
    cols = ["ip", "total_attempts", "fail_count", "fail_ratio", "users_count", "score"]
    to_show = scored[cols].sort_values(["fail_ratio", "fail_count", "total_attempts"], ascending=False, kind="stable")
    print("\n[INFO] Top IPs por ratio de fallos:")
    print(to_show.to_string(index=False, formatters={"fail_ratio": "{:.4f}".format, "score": "{:.1f}".format}))

    # Inserción de anomalías
    anom = scored[scored["is_anomaly"]].copy()
    print(f"\n[INFO] Anomalías detectadas: {len(anom)}")
    if anom.empty:
        print("\n[INFO] No se detectaron anomalías.")
        return

    for _, row in anom.iterrows():
        extra = {
            "window_hours": WINDOW_HOURS,
            "features": {
                "total_attempts": int(row["total_attempts"]),
                "fail_count": int(row["fail_count"]),
                "success_count": int(row["success_count"]),
                "fail_ratio": float(round(row["fail_ratio"], 4)),
                "users_count": int(row["users_count"]),
            },
            "model": {"type": "IsolationForest", **IFOREST_PARAMS},
        }
        if DRY_RUN:
            print(
                "[DRY_RUN] INSERT security_alerts:",
                (None, row["ip"], float(row["score"]), "iforest_ip", json.dumps(extra, ensure_ascii=False))
            )
        else:
            insert_alert(username=None, ip=row["ip"], risk=row["score"], label="iforest_ip", extra_dict=extra)

    print("\n[INFO] Listo.")


if __name__ == "__main__":
    main()
