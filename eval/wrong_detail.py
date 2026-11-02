"""틀린 항목마다 정답·규칙·에이전트 판정, 근거, 도구 호출, 메모를 나란히 출력한다(분석용).

  python eval/wrong_detail.py out/gpt-6-luna/results.json > eval/wrong_detail_gpt-6-luna.txt
"""
import json
import sys

sys.path.insert(0, "src")
from sbom_agent.cli import read_csv  # noqa: E402

gold = {r["key"]: r for r in read_csv("eval/gold30.csv")}
for path in sys.argv[1:]:
    rows = {r["key"]: r for r in json.load(open(path, encoding="utf-8"))}
    print(f"\n######## {path}")
    for k in sorted(gold):
        r, g = rows[k], gold[k]
        if r["agent_tier"] == g["gold_tier"].strip().upper():
            continue
        ag = r["agent"] or {}
        print(f"\n=== {k}  정답 {g['gold_tier']} | 규칙 {r['rule_tier']} ({'; '.join(r['rule_reasons'])}) "
              f"| 에이전트 {r['agent_tier']} (conf {ag.get('confidence')})")
        print(f"  메모: {g['memo']}")
        print(f"  CVSS {r['cvss']} EPSS {r['epss']} KEV {r['in_kev']} 직접사용 {len(r['direct_usages'])}")
        print(f"  경로: {ag.get('exploit_path')}")
        for e in ag.get("evidence", []):
            print(f"  - 근거: {e}")
        print(f"  도구({len(r['agent_trace'])}): {' / '.join(r['agent_trace'])}")
        if r["agent_error"]:
            print(f"  오류: {r['agent_error']}")
