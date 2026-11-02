"""정답 작성 분량을 줄이기 위해 gold.csv 에서 라이브러리별로 고르게 N건을 뽑는다.

판정 결과(results.json)는 읽지 않고 gold.csv 의 package 칸만 기준으로 삼는다.
  1) 라이브러리마다 1건씩 (N보다 종류가 많으면 건수 많은 순으로 N종)
  2) 남는 자리는 건수 많은 라이브러리부터 1건씩 더
  라이브러리 안에서는 고정 시드로 무작위 선택한다.

  PYTHONPATH=src python eval/sample_gold.py --gold eval/gold.csv --out eval/gold30.csv --n 30
  # 검증 세트: 이미 정답 대상으로 쓴 key 는 뺀다
  PYTHONPATH=src python eval/sample_gold.py --gold eval/gold.csv --exclude eval/gold30.csv --n 15 --seed 20261103 --out eval/gold_val15.csv
"""
from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict

from sbom_agent.cli import read_csv  # 엑셀이 저장한 CP949 파일도 읽는다


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--gold", default="eval/gold.csv")
    p.add_argument("--out", default="eval/gold30.csv")
    p.add_argument("--n", type=int, default=30)
    p.add_argument("--seed", type=int, default=20261102)
    p.add_argument("--exclude", action="append", default=[], help="이 csv 의 key 는 뽑지 않는다(여러 번 줄 수 있음)")
    a = p.parse_args()

    rows = read_csv(a.gold)
    fields = list(rows[0].keys())
    excluded = {r["key"] for path in a.exclude for r in read_csv(path)}
    rows = [r for r in rows if r["key"] not in excluded]

    rng = random.Random(a.seed)
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[r["package"]].append(r)
    for g in groups.values():
        rng.shuffle(g)
    # 건수 많은 순, 같으면 이름순으로 돌아가며 1건씩
    order = sorted(groups, key=lambda k: (-len(groups[k]), k))

    picked: list[dict] = []
    while len(picked) < min(a.n, len(rows)):
        for k in order:
            if groups[k] and len(picked) < a.n:
                picked.append(groups[k].pop())

    picked.sort(key=lambda r: r["key"])
    with open(a.out, "w", encoding="utf-8-sig", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        w.writerows(picked)
    print(f"{len(rows)}건 중 {len(picked)}건 → {a.out}" + (f" (제외 {len(excluded)}건)" if excluded else ""))


if __name__ == "__main__":
    main()
