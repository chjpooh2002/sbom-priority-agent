"""명령 세 가지.

  python -m sbom_agent.cli run   --scan out/grype.json --src sample-app --out out
  python -m sbom_agent.cli gold  --results out/results.json --out eval/gold.csv
  python -m sbom_agent.cli eval  --results out/results.json --gold eval/gold.csv
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .enrich import EPSS_URL, KEV_URL, enrich
from .load import load_grype
from .models import Tier
from .reach import annotate
from .score import apply_rules, cvss_only_tier

ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def cmd_run(a) -> None:
    findings = load_grype(a.scan)
    snapshot = enrich(findings, offline=a.offline, kev_file=a.kev_file, epss_file=a.epss_file)
    annotate(findings, a.src)
    apply_rules(findings)

    decisions = [(None, [], "에이전트 단계 생략")] * len(findings)
    if not a.no_agent:
        from .agent import judge_all
        decisions = asyncio.run(judge_all(findings, a.src, a.concurrency, a.model))

    rows = []
    for f, (d, trace, err) in zip(findings, decisions):
        rows.append({
            "key": f.key, "vuln_id": f.vuln_id, "package": f.package, "version": f.version,
            "cvss": f.cvss, "epss": f.epss, "in_kev": f.in_kev, "fixed_versions": f.fixed_versions,
            "direct_usages": f.direct_usages,
            "cvss_only_tier": cvss_only_tier(f).value,
            "rule_tier": f.rule_tier.value, "rule_reasons": f.rule_reasons,
            "agent_tier": d.tier.value if d else f.rule_tier.value,
            "agent": d.model_dump(mode="json") if d else None,
            "agent_trace": trace, "agent_error": err,
        })
    rows.sort(key=lambda r: (ORDER[r["agent_tier"]], -(r["epss"] or 0), -(r["cvss"] or 0)))

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_report(rows), encoding="utf-8")
    write_snapshot(out, a, snapshot)
    print(f"{len(rows)}건 처리 → {out/'results.json'}, {out/'report.md'}")


def write_snapshot(out: Path, a, snapshot: dict) -> None:
    """측정에 쓴 외부 지표 원본과 도구·DB 버전을 남긴다. 스냅샷은 --kev-file/--epss-file 로 다시 넣을 수 있다."""
    for name, data in (("kev_snapshot.json", snapshot["kev"]), ("epss_snapshot.json", snapshot["epss"])):
        (out / name).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    desc = json.loads(Path(a.scan).read_text(encoding="utf-8")).get("descriptor", {})
    sbom = Path(a.scan).parent / "sbom.cdx.json"
    syft = None
    if sbom.exists():
        tools = json.loads(sbom.read_text(encoding="utf-8")).get("metadata", {}).get("tools") or {}
        comps = tools.get("components", []) if isinstance(tools, dict) else tools
        syft = next((t.get("version") for t in comps if t.get("name") == "syft"), None)
    kev = snapshot["kev"]
    meta = {
        "run_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "scan_file": Path(a.scan).as_posix(),
        "scan_date": desc.get("timestamp"),
        "syft_version": syft,
        "grype_version": desc.get("version"),
        "grype_db_built": ((desc.get("db") or {}).get("status") or {}).get("built"),
        "grype_db_schema": ((desc.get("db") or {}).get("status") or {}).get("schemaVersion"),
        "kev_source": a.kev_file or KEV_URL,
        "kev_catalog_version": kev.get("catalogVersion"),
        "kev_date_released": kev.get("dateReleased"),
        "epss_source": a.epss_file or EPSS_URL,
        "epss_dates": sorted({r.get("date") for r in snapshot["epss"]["data"] if r.get("date")}),
        "epss_rows": len(snapshot["epss"]["data"]),
        "offline": a.offline,
    }
    (out / "scan_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def render_report(rows: list[dict]) -> str:
    lines = ["# 오픈소스 취약점 조치 우선순위 보고서", "",
             "| 순위 | 취약점 | 라이브러리 | 심각도 | 악용 가능성 | 실제 악용 | 직접 사용 | 규칙 | 최종 |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for i, r in enumerate(rows, 1):
        lines.append(
            f"| {i} | {r['vuln_id']} | {r['package']} {r['version']} | {r['cvss'] or '-'} | "
            f"{'-' if r['epss'] is None else format(r['epss'], '.3f')} | {'예' if r['in_kev'] else '아니오'} | "
            f"{'예' if r['direct_usages'] else '아니오'} | {r['rule_tier']} | **{r['agent_tier']}** |")
    lines.append("")
    for r in rows:
        if r["agent_tier"] not in ("P1", "P2") and not (r["agent"] and r["agent"]["changed_from_rule"]):
            continue
        lines += [f"## {r['agent_tier']} · {r['vuln_id']} · {r['package']} {r['version']}", ""]
        ag = r["agent"]
        if ag:
            if ag["changed_from_rule"]:
                lines.append(f"규칙 판정 {r['rule_tier']} → 최종 {ag['tier']} (확신도 {ag['confidence']:.2f})")
                lines.append("")
            lines += [f"**공격 경로**: {ag['exploit_path']}", "", "**근거**", ""]
            lines += [f"- {e}" for e in ag["evidence"]]
            lines += ["", f"**조치안**: {ag['remediation']}", ""]
        else:
            lines += ["규칙 근거: " + ", ".join(r["rule_reasons"]), ""]
            if r["agent_error"]:
                lines += [f"(에이전트 실패: {r['agent_error']})", ""]
    return "\n".join(lines)


def cmd_gold(a) -> None:
    rows = json.loads(Path(a.results).read_text(encoding="utf-8"))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8-sig") as fp:
        w = csv.writer(fp)
        w.writerow(["key", "vuln_id", "package", "version", "gold_tier", "memo"])
        for r in sorted(rows, key=lambda r: r["key"]):  # 판정 순서가 보이지 않게 이름순
            w.writerow([r["key"], r["vuln_id"], r["package"], r["version"], "", ""])
    print(f"정답 작성용 파일 → {a.out}  (gold_tier 칸에 P1~P4 를 직접 채우세요. 결과 파일은 보지 말고)")


def score(pred: list[str], gold: list[str]) -> dict:
    n = len(gold)
    exact = sum(p == g for p, g in zip(pred, gold))
    near = sum(abs(ORDER[p] - ORDER[g]) <= 1 for p, g in zip(pred, gold))
    must = [i for i, g in enumerate(gold) if g in ("P1", "P2")]
    caught = sum(pred[i] in ("P1", "P2") for i in must)
    false_alarm = sum(p in ("P1", "P2") and g in ("P3", "P4") for p, g in zip(pred, gold))
    return {"건수": n, "정확히 일치": exact / n, "한 단계 이내": near / n,
            "급한 건 놓치지 않은 비율": (caught / len(must)) if must else None,
            "불필요한 긴급 경보 건수": false_alarm}


def cmd_eval(a) -> None:
    rows = {r["key"]: r for r in json.loads(Path(a.results).read_text(encoding="utf-8"))}
    with open(a.gold, encoding="utf-8-sig") as fp:
        gold = {r["key"]: r["gold_tier"].strip().upper() for r in csv.DictReader(fp) if r["gold_tier"].strip()}
    keys = [k for k in gold if k in rows]
    if not keys:
        raise SystemExit("채점할 항목이 없습니다. gold_tier 칸을 채웠는지 확인하세요.")
    g = [gold[k] for k in keys]
    table = {
        "심각도 점수만": score([rows[k]["cvss_only_tier"] for k in keys], g),
        "규칙": score([rows[k]["rule_tier"] for k in keys], g),
        "규칙 + 에이전트": score([rows[k]["agent_tier"] for k in keys], g),
    }
    cols = list(next(iter(table.values())).keys())
    md = ["| 방식 | " + " | ".join(cols) + " |", "| --- " * (len(cols) + 1) + "|"]
    for name, s in table.items():
        cells = [(f"{v:.0%}" if isinstance(v, float) else str(v)) for v in s.values()]
        md.append(f"| {name} | " + " | ".join(cells) + " |")
    wrong = [f"- {k}: 정답 {gold[k]}, 최종 {rows[k]['agent_tier']}, 규칙 {rows[k]['rule_tier']}"
             for k in keys if rows[k]["agent_tier"] != gold[k]]
    text = "\n".join(md + ["", "### 최종 판정이 틀린 항목", ""] + (wrong or ["- 없음"]))
    print(text)
    if a.out:
        Path(a.out).write_text("# 정확도 측정 결과\n\n" + text + "\n", encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser(prog="sbom_agent")
    sp = p.add_subparsers(dest="cmd", required=True)

    r = sp.add_parser("run", help="스캔 결과를 판정해 보고서를 만든다")
    r.add_argument("--scan", required=True, help="grype -o json 결과 파일")
    r.add_argument("--src", required=True, help="분석 대상 프로젝트 폴더")
    r.add_argument("--out", default="out")
    r.add_argument("--offline", action="store_true", help="외부 지표를 캐시나 지정 파일에서만 읽는다")
    r.add_argument("--kev-file")
    r.add_argument("--epss-file")
    r.add_argument("--no-agent", action="store_true", help="규칙 판정까지만 한다")
    r.add_argument("--model")
    r.add_argument("--concurrency", type=int, default=4)
    r.set_defaults(func=cmd_run)

    g = sp.add_parser("gold", help="정답 작성용 빈 표를 만든다")
    g.add_argument("--results", required=True)
    g.add_argument("--out", default="eval/gold.csv")
    g.set_defaults(func=cmd_gold)

    e = sp.add_parser("eval", help="세 방식의 정확도를 비교한다")
    e.add_argument("--results", required=True)
    e.add_argument("--gold", required=True)
    e.add_argument("--out", default="eval/result.md")
    e.set_defaults(func=cmd_eval)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
