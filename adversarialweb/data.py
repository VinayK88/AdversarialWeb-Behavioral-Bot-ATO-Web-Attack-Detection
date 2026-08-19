from __future__ import annotations

import numpy as np
import pandas as pd


ATTACK_TYPES = ("benign", "scraping", "credential_stuffing", "ato", "bot")


def _clip(rng: np.random.Generator, mean: float, sd: float, n: int, low: float = 0.0, high: float = 1.0) -> np.ndarray:
    return np.clip(rng.normal(mean, sd, n), low, high)


def generate_sessions(n: int = 2400, seed: int = 42) -> pd.DataFrame:
    """Generate deterministic synthetic web-security session telemetry.

    The dataset is intentionally synthetic and designed for portfolio evaluation.
    It contains overlap between benign and malicious behavior so false positives,
    false negatives, threshold tuning, and investigation workflows are meaningful.
    """
    if n < 200:
        raise ValueError("n must be at least 200 to preserve class coverage")

    rng = np.random.default_rng(seed)
    labels = rng.choice(
        ATTACK_TYPES,
        size=n,
        p=[0.68, 0.10, 0.09, 0.05, 0.08],
    )

    rows: list[dict[str, object]] = []
    countries = np.array(["US", "IN", "DE", "GB", "BR", "SG", "CA", "NL"])
    methods = np.array(["GET", "POST"])
    endpoints = {
        "benign": np.array(["browse", "search", "login", "checkout", "api"]),
        "scraping": np.array(["search", "product", "api"]),
        "credential_stuffing": np.array(["login", "auth"]),
        "ato": np.array(["login", "account", "checkout"]),
        "bot": np.array(["api", "search", "login"]),
    }

    for i, label in enumerate(labels):
        if label == "benign":
            rpm = max(0.2, rng.lognormal(1.7, 0.45))
            inter_cv = _clip(rng, 0.78, 0.18, 1)[0]
            endpoint_entropy = _clip(rng, 0.72, 0.16, 1)[0]
            login_fail = _clip(rng, 0.08, 0.08, 1)[0]
            accounts_per_ip = max(1.0, rng.normal(1.4, 0.6))
            ips_per_account = max(1.0, rng.normal(1.3, 0.5))
            ua_rotation = _clip(rng, 0.04, 0.05, 1)[0]
            cookie_reuse = _clip(rng, 0.09, 0.08, 1)[0]
            header_consistency = _clip(rng, 0.95, 0.04, 1)[0]
            tls_consistency = _clip(rng, 0.96, 0.03, 1)[0]
            nav_entropy = _clip(rng, 0.76, 0.14, 1)[0]
            status_4xx = _clip(rng, 0.05, 0.05, 1)[0]
            session_minutes = max(0.5, rng.normal(12.0, 6.0))
            automation = _clip(rng, 0.08, 0.08, 1)[0]
        elif label == "scraping":
            rpm = max(2.0, rng.lognormal(3.4, 0.45))
            inter_cv = _clip(rng, 0.24, 0.12, 1)[0]
            endpoint_entropy = _clip(rng, 0.46, 0.18, 1)[0]
            login_fail = _clip(rng, 0.03, 0.04, 1)[0]
            accounts_per_ip = max(1.0, rng.normal(1.3, 0.5))
            ips_per_account = max(1.0, rng.normal(1.1, 0.3))
            ua_rotation = _clip(rng, 0.42, 0.18, 1)[0]
            cookie_reuse = _clip(rng, 0.18, 0.12, 1)[0]
            header_consistency = _clip(rng, 0.66, 0.13, 1)[0]
            tls_consistency = _clip(rng, 0.74, 0.12, 1)[0]
            nav_entropy = _clip(rng, 0.31, 0.15, 1)[0]
            status_4xx = _clip(rng, 0.10, 0.08, 1)[0]
            session_minutes = max(1.0, rng.normal(20.0, 8.0))
            automation = _clip(rng, 0.78, 0.12, 1)[0]
        elif label == "credential_stuffing":
            rpm = max(1.0, rng.lognormal(2.15, 0.35))
            inter_cv = _clip(rng, 0.44, 0.16, 1)[0]
            endpoint_entropy = _clip(rng, 0.20, 0.10, 1)[0]
            login_fail = _clip(rng, 0.78, 0.13, 1)[0]
            accounts_per_ip = max(1.0, rng.normal(5.7, 1.8))
            ips_per_account = max(1.0, rng.normal(3.0, 1.0))
            ua_rotation = _clip(rng, 0.55, 0.17, 1)[0]
            cookie_reuse = _clip(rng, 0.24, 0.14, 1)[0]
            header_consistency = _clip(rng, 0.61, 0.15, 1)[0]
            tls_consistency = _clip(rng, 0.68, 0.14, 1)[0]
            nav_entropy = _clip(rng, 0.16, 0.09, 1)[0]
            status_4xx = _clip(rng, 0.67, 0.16, 1)[0]
            session_minutes = max(0.5, rng.normal(6.0, 2.5))
            automation = _clip(rng, 0.71, 0.14, 1)[0]
            if rng.random() < 0.35:
                login_fail = _clip(rng, 0.46, 0.12, 1)[0]
                accounts_per_ip = max(1.0, rng.normal(2.7, 0.9))
                ips_per_account = max(1.0, rng.normal(2.0, 0.7))
                ua_rotation = _clip(rng, 0.28, 0.12, 1)[0]
                status_4xx = _clip(rng, 0.39, 0.13, 1)[0]
                automation = _clip(rng, 0.48, 0.13, 1)[0]
        elif label == "ato":
            rpm = max(0.5, rng.lognormal(1.9, 0.38))
            inter_cv = _clip(rng, 0.58, 0.18, 1)[0]
            endpoint_entropy = _clip(rng, 0.58, 0.14, 1)[0]
            login_fail = _clip(rng, 0.22, 0.14, 1)[0]
            accounts_per_ip = max(1.0, rng.normal(1.8, 0.8))
            ips_per_account = max(1.0, rng.normal(3.7, 1.2))
            ua_rotation = _clip(rng, 0.30, 0.16, 1)[0]
            cookie_reuse = _clip(rng, 0.68, 0.15, 1)[0]
            header_consistency = _clip(rng, 0.79, 0.11, 1)[0]
            tls_consistency = _clip(rng, 0.76, 0.12, 1)[0]
            nav_entropy = _clip(rng, 0.53, 0.16, 1)[0]
            status_4xx = _clip(rng, 0.15, 0.10, 1)[0]
            session_minutes = max(0.5, rng.normal(9.0, 4.0))
            automation = _clip(rng, 0.43, 0.16, 1)[0]
        else:
            rpm = max(1.0, rng.lognormal(3.0, 0.55))
            inter_cv = _clip(rng, 0.29, 0.16, 1)[0]
            endpoint_entropy = _clip(rng, 0.36, 0.20, 1)[0]
            login_fail = _clip(rng, 0.28, 0.18, 1)[0]
            accounts_per_ip = max(1.0, rng.normal(2.7, 1.2))
            ips_per_account = max(1.0, rng.normal(1.8, 0.7))
            ua_rotation = _clip(rng, 0.47, 0.20, 1)[0]
            cookie_reuse = _clip(rng, 0.31, 0.16, 1)[0]
            header_consistency = _clip(rng, 0.58, 0.17, 1)[0]
            tls_consistency = _clip(rng, 0.63, 0.16, 1)[0]
            nav_entropy = _clip(rng, 0.27, 0.17, 1)[0]
            status_4xx = _clip(rng, 0.24, 0.16, 1)[0]
            session_minutes = max(0.5, rng.normal(14.0, 6.0))
            automation = _clip(rng, 0.72, 0.16, 1)[0]

        if label == "benign" and rng.random() < 0.12:
            rpm = max(rpm, rng.lognormal(2.65, 0.35))
            inter_cv = min(inter_cv, _clip(rng, 0.48, 0.14, 1)[0])
            accounts_per_ip = max(accounts_per_ip, rng.normal(2.6, 0.8))
            ua_rotation = max(ua_rotation, _clip(rng, 0.20, 0.10, 1)[0])
            automation = max(automation, _clip(rng, 0.38, 0.12, 1)[0])
            status_4xx = max(status_4xx, _clip(rng, 0.15, 0.08, 1)[0])
        elif label != "benign" and rng.random() < 0.14:
            rpm = 0.55 * rpm + 0.45 * rng.lognormal(1.8, 0.35)
            inter_cv = 0.60 * inter_cv + 0.40 * _clip(rng, 0.72, 0.14, 1)[0]
            ua_rotation = 0.65 * ua_rotation + 0.35 * _clip(rng, 0.08, 0.06, 1)[0]
            header_consistency = 0.60 * header_consistency + 0.40 * _clip(rng, 0.93, 0.05, 1)[0]
            tls_consistency = 0.60 * tls_consistency + 0.40 * _clip(rng, 0.94, 0.04, 1)[0]
            automation = 0.65 * automation + 0.35 * _clip(rng, 0.14, 0.09, 1)[0]

        endpoint = str(rng.choice(endpoints[label]))
        method = "POST" if endpoint in {"login", "auth", "checkout", "account"} else str(rng.choice(methods, p=[0.86, 0.14]))

        rows.append({
            "session_id": f"sess-{i:05d}",
            "ip": f"198.51.{i % 255}.{(i * 17) % 255}",
            "asn": int(rng.choice([13335, 16509, 15169, 8075, 24940, 14061, 7922])),
            "country": str(rng.choice(countries)),
            "http_version": str(rng.choice(["h2", "h3", "http/1.1"], p=[0.58, 0.20, 0.22])),
            "method": method,
            "endpoint_family": endpoint,
            "user_agent_family": str(rng.choice(["Chrome", "Safari", "Firefox", "Edge", "Headless", "Unknown"])),
            "tls_fingerprint": f"ja4-{rng.integers(100, 999)}",
            "requests_per_min": round(float(rpm), 3),
            "interarrival_cv": round(float(inter_cv), 3),
            "endpoint_entropy": round(float(endpoint_entropy), 3),
            "login_fail_rate": round(float(login_fail), 3),
            "accounts_per_ip": round(float(accounts_per_ip), 3),
            "ips_per_account": round(float(ips_per_account), 3),
            "ua_rotation_rate": round(float(ua_rotation), 3),
            "cookie_reuse_rate": round(float(cookie_reuse), 3),
            "header_consistency": round(float(header_consistency), 3),
            "tls_consistency": round(float(tls_consistency), 3),
            "navigation_entropy": round(float(nav_entropy), 3),
            "status_4xx_rate": round(float(status_4xx), 3),
            "session_minutes": round(float(session_minutes), 3),
            "automation_score": round(float(automation), 3),
            "attack_type": label,
            "is_malicious": int(label != "benign"),
        })

    return pd.DataFrame(rows)
