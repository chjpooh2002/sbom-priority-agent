"""외부 지표 보강: 악용 가능성 점수(EPSS)와 실제 악용 확인 목록(CISA KEV).

내려받은 값은 .cache/ 에 저장해 두고, --offline 이면 캐시나 지정 파일만 쓴다.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import httpx

from .models import Finding

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE = Path(".cache")


def _cached_get(url: str, name: str, max_age_h: float, offline: bool, params: dict | None = None) -> dict:
    CACHE.mkdir(exist_ok=True)
    f = CACHE / name
    if f.exists() and (offline or time.time() - f.stat().st_mtime < max_age_h * 3600):
        return json.loads(f.read_text(encoding="utf-8"))
    if offline:
        raise FileNotFoundError(f"오프라인 모드인데 캐시가 없습니다: {f}")
    r = httpx.get(url, params=params, timeout=30)
    r.raise_for_status()
    f.write_text(r.text, encoding="utf-8")
    return r.json()


def load_kev(offline: bool = False, kev_file: str | None = None) -> dict:
    return json.loads(Path(kev_file).read_text(encoding="utf-8")) if kev_file \
        else _cached_get(KEV_URL, "kev.json", 24, offline)


def load_epss(cves: list[str], offline: bool = False, epss_file: str | None = None) -> list[dict]:
    if epss_file:
        rows = json.loads(Path(epss_file).read_text(encoding="utf-8")).get("data", [])
    else:
        rows = []
        cves = sorted(set(cves))
        for i in range(0, len(cves), 50):
            chunk = cves[i:i + 50]
            # hash() 는 실행마다 달라지므로 내용 기준 고정 이름을 쓴다
            name = f"epss_{hashlib.sha256(','.join(chunk).encode()).hexdigest()[:16]}.json"
            rows += _cached_get(EPSS_URL, name, 24, offline, {"cve": ",".join(chunk)}).get("data", [])
    return rows


def enrich(findings: list[Finding], offline: bool = False,
           kev_file: str | None = None, epss_file: str | None = None) -> dict:
    """보강하고, 이번에 쓴 원본 지표를 돌려준다(측정 재현용 스냅샷)."""
    kev_data = load_kev(offline, kev_file)
    kev = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    cves = [c for f in findings for c in [f.vuln_id, *f.aliases] if c.startswith("CVE-")]
    epss_rows = load_epss(cves, offline, epss_file)
    epss = {r["cve"]: (float(r["epss"]), float(r["percentile"])) for r in epss_rows}
    for f in findings:
        ids = [f.vuln_id, *f.aliases]
        f.in_kev = any(i in kev for i in ids)
        hits = [epss[i] for i in ids if i in epss]
        if hits:
            f.epss, f.epss_percentile = max(hits)
    return {"kev": kev_data, "epss": {"data": epss_rows}}
