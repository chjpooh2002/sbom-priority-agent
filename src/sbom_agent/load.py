"""취약점 스캐너(grype) 결과 JSON을 Finding 목록으로 바꾼다."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote

from .models import Finding


def _group_from_purl(purl: str) -> str:
    # pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    if not purl.startswith("pkg:maven/"):
        return ""
    rest = unquote(purl[len("pkg:maven/"):]).split("@")[0]
    return rest.split("/")[0] if "/" in rest else ""


def _best_cvss(vuln: dict) -> float | None:
    scores = []
    for c in vuln.get("cvss") or []:
        s = (c.get("metrics") or {}).get("baseScore")
        if s is not None:
            scores.append(float(s))
    return max(scores) if scores else None


def load_grype(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: dict[str, Finding] = {}
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        a = m.get("artifact", {})
        ids = [v.get("id", "")] + [r.get("id", "") for r in m.get("relatedVulnerabilities") or []]
        ids = [i for i in dict.fromkeys(ids) if i]
        cves = [i for i in ids if i.startswith("CVE-")]
        primary = cves[0] if cves else ids[0]

        cvss = _best_cvss(v)
        if cvss is None:
            for r in m.get("relatedVulnerabilities") or []:
                cvss = _best_cvss(r) or cvss

        key = f"{primary}|{a.get('name')}"
        if key in out:  # 같은 라이브러리가 여러 위치에서 잡힌 경우 한 건으로 합친다
            continue
        out[key] = Finding(
            key=key,
            vuln_id=primary,
            aliases=[i for i in ids if i != primary],
            package=a.get("name", ""),
            version=a.get("version", ""),
            purl=a.get("purl", ""),
            group=_group_from_purl(a.get("purl", "")),
            severity=v.get("severity", "Unknown"),
            cvss=cvss,
            fixed_versions=(v.get("fix") or {}).get("versions") or [],
            description=(v.get("description") or "")[:600],
        )
    return list(out.values())
