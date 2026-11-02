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
import re
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

    targets = [] if a.no_agent else findings
    if a.keys and not a.no_agent:
        with open(a.keys, encoding="utf-8-sig", newline="") as fp:
            wanted = {r["key"] for r in csv.DictReader(fp)}
        targets = [f for f in findings if f.key in wanted]
        if missing := wanted - {f.key for f in findings}:
            print(f"경고: 스캔 결과에 없는 key {len(missing)}건은 건너뜀")
    judged: dict[str, tuple] = {}
    if targets:
        from .agent import judge_all
        results = asyncio.run(judge_all(targets, a.src, a.concurrency, a.model))
        judged = {f.key: r for f, r in zip(targets, results)}

    rows = []
    for f in findings:
        d, trace, err, stats = judged.get(f.key, (None, [], None, None))
        status = "skipped" if f.key not in judged else ("ok" if d else "failed")
        rows.append({
            "key": f.key, "vuln_id": f.vuln_id, "package": f.package, "version": f.version,
            "cvss": f.cvss, "epss": f.epss, "in_kev": f.in_kev, "fixed_versions": f.fixed_versions,
            "direct_usages": f.direct_usages,
            "cvss_only_tier": cvss_only_tier(f).value,
            "rule_tier": f.rule_tier.value, "rule_reasons": f.rule_reasons,
            "agent_tier": d.tier.value if d else f.rule_tier.value,
            "agent": d.model_dump(mode="json") if d else None,
            "agent_status": status,  # ok / failed / skipped(에이전트 대상 아님)
            "agent_trace": trace, "agent_error": err,
            "agent_seconds": stats["seconds"] if stats else None,
            "agent_usage": stats["usage"] if stats else None,
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


METHODS = {"심각도 점수만": "cvss_only_tier", "규칙": "rule_tier", "규칙 + 에이전트": "agent_tier"}
REF = re.compile(r"([\w.\-/\\]+\.[A-Za-z]\w*):(\d+)")  # evidence 안의 "경로:줄번호"


def agent_status(r: dict) -> str:
    if "agent_status" in r:
        return r["agent_status"]
    if r.get("agent"):
        return "ok"
    return "failed" if r.get("agent_error") and r["agent_error"] != "에이전트 단계 생략" else "skipped"


def check_ref(path: str, line: int, src: Path) -> bool:
    """근거에 적힌 파일이 분석 대상 폴더 안에 있고 그 줄이 존재하는지."""
    p = path.replace("\\", "/").removeprefix("./")
    if p.startswith(src.name + "/"):
        p = p[len(src.name) + 1:]
    f = (src / p).resolve()
    if src.resolve() not in f.parents or not f.is_file():
        return False
    return 1 <= line <= len(f.read_text(encoding="utf-8", errors="ignore").splitlines())


def agent_metrics(all_rows: list[dict], gold: dict[str, str], src: Path) -> list[str]:
    ok = [r for r in all_rows if agent_status(r) == "ok"]
    tried = [r for r in all_rows if agent_status(r) in ("ok", "failed")]
    if not tried:
        return ["- 에이전트로 판정한 건이 없습니다."]

    changed = [r for r in ok if r["agent_tier"] != r["rule_tier"]]
    closer = farther = same = 0
    for r in changed:
        if r["key"] not in gold:
            continue
        g = ORDER[gold[r["key"]]]
        d_rule, d_agent = abs(ORDER[r["rule_tier"]] - g), abs(ORDER[r["agent_tier"]] - g)
        closer += d_agent < d_rule
        farther += d_agent > d_rule
        same += d_agent == d_rule

    refs = [(m.group(1), int(m.group(2))) for r in ok for e in r["agent"]["evidence"] for m in REF.finditer(e)]
    verified = sum(check_ref(p, n, src) for p, n in refs)
    no_ref = sum(not REF.search(e) for r in ok for e in r["agent"]["evidence"])

    secs = [r["agent_seconds"] for r in tried if r.get("agent_seconds") is not None]
    toks = [r["agent_usage"]["total_tokens"] for r in tried if r.get("agent_usage")]
    n_gold_changed = closer + farther + same
    return [
        f"- 에이전트 판정 {len(tried)}건(성공 {len(ok)}, 실패 {len(tried) - len(ok)}), "
        f"실패율 {(len(tried) - len(ok)) / len(tried):.0%}",
        f"- 규칙 판정을 바꾼 건수: {len(changed)}건 (성공 {len(ok)}건 중)",
        f"  - 채점 대상 중 바꾼 {n_gold_changed}건: 정답에 가까워짐 {closer} / 멀어짐 {farther} / 거리 같음 {same}",
        f"- 근거 검증률: {verified}/{len(refs)}" + (f" ({verified / len(refs):.0%})" if refs else "")
        + f" — evidence 의 '경로:줄번호'가 `{src.as_posix()}` 안에 실제로 있는 비율. 경로 없는 근거 항목 {no_ref}개",
        f"- 건당 평균 시간: " + (f"{sum(secs) / len(secs):.1f}초 ({len(secs)}건)" if secs else "기록 없음"),
        f"- 건당 평균 토큰: " + (f"{sum(toks) / len(toks):,.0f} ({len(toks)}건)" if toks else "기록 없음"),
    ]


def alert_metrics(all_rows: list[dict]) -> list[str]:
    n = len(all_rows)
    base = sum(r["cvss_only_tier"] in ("P1", "P2") for r in all_rows)
    md = [f"전체 {n}건 중 P1·P2 로 남은 건수. 감소율은 '심각도 점수만' 대비.", "",
          "| 방식 | P1·P2 건수 | 전체 대비 | 감소율 |", "| --- | --- | --- | --- |"]
    for name, col in METHODS.items():
        k = sum(r[col] in ("P1", "P2") for r in all_rows)
        red = f"{(base - k) / base:.0%}" if base else "-"
        md.append(f"| {name} | {k} | {k / n:.0%} | {red} |")
    return md


def cmd_eval(a) -> None:
    all_rows = json.loads(Path(a.results).read_text(encoding="utf-8"))
    rows = {r["key"]: r for r in all_rows}
    with open(a.gold, encoding="utf-8-sig") as fp:
        gold = {r["key"]: r["gold_tier"].strip().upper() for r in csv.DictReader(fp) if r["gold_tier"].strip()}
    keys = [k for k in gold if k in rows]
    if not keys:
        raise SystemExit("채점할 항목이 없습니다. gold_tier 칸을 채웠는지 확인하세요.")
    g = [gold[k] for k in keys]
    table = {name: score([rows[k][col] for k in keys], g) for name, col in METHODS.items()}
    cols = list(next(iter(table.values())).keys())
    md = ["| 방식 | " + " | ".join(cols) + " |", "| --- " * (len(cols) + 1) + "|"]
    for name, s in table.items():
        cells = [(f"{v:.0%}" if isinstance(v, float) else str(v)) for v in s.values()]
        md.append(f"| {name} | " + " | ".join(cells) + " |")
    wrong = [f"- {k}: 정답 {gold[k]}, 최종 {rows[k]['agent_tier']}, 규칙 {rows[k]['rule_tier']}"
             for k in keys if rows[k]["agent_tier"] != gold[k]]
    text = "\n".join(md + ["", "### 경보 감소 (전체 결과 기준)", ""] + alert_metrics(all_rows)
                     + ["", "### 에이전트", ""] + agent_metrics(all_rows, gold, Path(a.src))
                     + ["", "### 최종 판정이 틀린 항목", ""] + (wrong or ["- 없음"]))
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
    r.add_argument("--keys", help="이 csv 의 key 칸에 있는 건만 에이전트로 판정한다(나머지는 규칙 판정 유지)")
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
    e.add_argument("--src", default="sample-app", help="근거 검증에 쓸 분석 대상 폴더")
    e.set_defaults(func=cmd_eval)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
