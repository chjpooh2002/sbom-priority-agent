"""정답 작성용 사실 표(gold30_sheet.md)를 만든다.

판정이 섞이지 않도록 results.json 은 읽지 않는다. grype 결과와 측정에 쓴 지표 스냅샷으로
load_grype → enrich → annotate 만 다시 돌리고, 규칙(apply_rules)은 부르지 않는다.

  PYTHONPATH=src python eval/make_sheet.py
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

from sbom_agent.enrich import enrich
from sbom_agent.load import load_grype
from sbom_agent.reach import annotate

GRADES = """| 등급 | 기준 |
| --- | --- |
| P1 긴급 | 외부 입력이 취약 기능에 닿고, 실제 악용 사례가 있거나 악용이 쉬움. 이번 주 조치 |
| P2 높음 | 공격 경로가 있으나 조건이 붙음. 다음 배포에 포함 |
| P3 보통 | 경로가 확인되지 않거나 전제 조건이 성립하지 않음. 정기 업데이트 때 |
| P4 낮음 | 코드와 프레임워크 어디서도 쓰이지 않음. 기록만 |"""


def cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").strip()


def full_descriptions(scan: str) -> dict[str, str]:
    """GHSA 대표 항목은 설명이 제목 한 줄뿐이라, 연관 항목(NVD 등)까지 보고 가장 긴 설명을 고른다.
    key 는 load_grype 와 같은 방식으로 만든다."""
    out: dict[str, str] = {}
    for m in json.loads(Path(scan).read_text(encoding="utf-8")).get("matches", []):
        v, rel = m.get("vulnerability", {}), m.get("relatedVulnerabilities") or []
        ids = [i for i in dict.fromkeys([v.get("id", "")] + [r.get("id", "") for r in rel]) if i]
        cves = [i for i in ids if i.startswith("CVE-")]
        key = f"{cves[0] if cves else ids[0]}|{m.get('artifact', {}).get('name')}"
        descs = [v.get("description") or ""] + [r.get("description") or "" for r in rel]
        best = max(descs, key=len)
        if len(best) > len(out.get(key, "")):
            out[key] = best
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--gold", default="eval/gold30.csv")
    p.add_argument("--scan", default="out/grype.json")
    p.add_argument("--kev-file", default="out/kev_snapshot.json")
    p.add_argument("--epss-file", default="out/epss_snapshot.json")
    p.add_argument("--meta", default="out/scan_meta.json")
    p.add_argument("--src", default="sample-app")
    p.add_argument("--notes", default="eval/library_notes.json")
    p.add_argument("--out", default="eval/gold30_sheet.md")
    a = p.parse_args()

    with open(a.gold, encoding="utf-8-sig", newline="") as fp:
        keys = [r["key"] for r in csv.DictReader(fp)]
    findings = load_grype(a.scan)
    enrich(findings, offline=True, kev_file=a.kev_file, epss_file=a.epss_file)
    annotate(findings, a.src)
    by_key = {f.key: f for f in findings}
    missing = [k for k in keys if k not in by_key]
    if missing:
        raise SystemExit(f"스캔 결과에 없는 key: {missing}")

    descs = full_descriptions(a.scan)
    notes = json.loads(Path(a.notes).read_text(encoding="utf-8"))
    meta = json.loads(Path(a.meta).read_text(encoding="utf-8")) if Path(a.meta).exists() else {}
    groups = defaultdict(list)
    for k in keys:
        groups[by_key[k].package].append(by_key[k])

    md = ["# 정답 작성용 사실 표", "",
          f"대상: `{a.gold}` {len(keys)}건, 라이브러리 {len(groups)}종. 정답은 `{a.gold}` 의 gold_tier 칸에 적는다.", "",
          "판정 결과는 이 표에 넣지 않는다. 라이브러리 이름순, 라이브러리 안에서는 key 이름순으로 정렬했다.", "",
          "\"직접 사용 위치\"는 `reach.py` 의 import 접두어 매칭 결과를 그대로 옮긴 것이다. 패키지 이름이 따로 지정되지 않은 "
          "라이브러리는 메이븐 그룹 아이디를 접두어로 쓰므로, 같은 그룹의 다른 모듈 import 도 잡힌다"
          "(예: spring-core·spring-context·spring-expression 에 spring-web 어노테이션 import, "
          "spring-boot 와 spring-boot-autoconfigure 는 서로의 import). log4j-core 는 log4j-api 패키지 import 로 잡힌 것이다. "
          "실제 사용 방식은 라이브러리별 요약을 함께 본다.", "",
          f"- 스캔: {meta.get('scan_date')} · syft {meta.get('syft_version')} · grype {meta.get('grype_version')}"
          f" · grype DB {meta.get('grype_db_built')}",
          f"- KEV {meta.get('kev_catalog_version')} · EPSS 기준일 {', '.join(meta.get('epss_dates') or []) or '-'}", "",
          "## 정답 기준 (README)", "", GRADES, ""]

    for pkg in sorted(groups):
        fs = sorted(groups[pkg], key=lambda f: f.key)
        md += [f"## {pkg} {fs[0].version} ({len(fs)}건)", "", "**이 서비스에서 쓰이는 방식**", ""]
        md += [f"- {line}" for line in notes.get(pkg, ["(요약 없음)"])]
        md += [""]
        for f in fs:
            epss = "-" if f.epss is None else f"{f.epss:.4f} (백분위 {f.epss_percentile:.1%})"
            usages = [u.replace("\\", "/") for u in f.direct_usages]
            md += [f"### `{f.key}`", "",
                   "| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |",
                   "| --- | --- | --- | --- | --- | --- |",
                   f"| {f.vuln_id} | {cell(', '.join(f.aliases)) or '-'} | {f.cvss if f.cvss is not None else '-'} | {epss} | "
                   f"{'등재' if f.in_kev else '미등재'} | {cell(', '.join(f.fixed_versions)) or '-'} |", "",
                   "- 직접 사용 위치(import 기준): " + ("; ".join(f"`{cell(u)}`" for u in usages) if usages else "없음"),
                   f"- 설명(앞 300자): {cell(descs.get(f.key, f.description)[:300])}", ""]

    Path(a.out).write_text("\n".join(md), encoding="utf-8")
    print(f"{len(keys)}건 → {a.out}")


if __name__ == "__main__":
    main()
