"""2차 판단 에이전트.

규칙 판정을 출발점으로, 코드와 설정 파일을 직접 읽어
(1) 실제 공격 경로가 있는지, (2) 우선순위를 한 단계 조정할 근거가 있는지,
(3) 구체 조치안을 만든다. 근거 없이 판정을 바꾸지 못하게 지시하고, 도구 호출 기록을 남긴다.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path

from agents import Agent, Runner, function_tool

from .models import AgentDecision, Finding

INSTRUCTIONS = """\
너는 자바 서비스의 오픈소스 취약점 담당 보안 엔지니어다.
입력으로 취약점 한 건과 규칙 기반 1차 판정이 주어진다. 할 일은 세 가지다.

1. 이 서비스에서 실제로 공격이 닿는 경로가 있는지 도구로 코드와 설정 파일을 직접 확인한다.
   - 우리 코드가 라이브러리를 직접 쓰지 않아도 프레임워크가 내부에서 쓰는 경우가 있다.
     어떤 기능을 통해 쓰이는지, 그 기능이 외부 입력을 받는지 확인한다.
   - 취약점 설명에 적힌 공격 전제 조건(특정 설정, 실행 환경, 배포 형태, 기능 활성화 여부)이
     이 서비스에서 성립하는지 설정 파일과 빌드 파일로 확인한다.
   - 외부 요청 값이 해당 기능까지 흘러가는지 컨트롤러부터 따라가 본다.
2. 최종 우선순위를 정한다(P1 긴급, P2 높음, P3 보통, P4 낮음).
   - 규칙 판정이 출발점이다. 바꿀 때는 위에서 찾은 구체 근거(파일 경로와 줄 번호)가 있어야 한다.
   - 근거가 부족하면 규칙 판정을 유지하고 confidence 를 낮춘다.
3. 조치안을 쓴다: 올릴 버전(수정 버전 목록에서 선택), 고칠 파일, 당장 할 수 있는 임시 완화책.

추측을 사실처럼 쓰지 않는다. evidence 에는 도구로 확인한 내용과 입력에 있는 외부 지표만 쓴다.
설명은 한국어로 쓴다.
"""

MAX_READ_LINES = 120


def build_agent(src_root: str | Path, trace: list[str], model: str | None = None) -> Agent:
    root = Path(src_root).resolve()

    def _safe(p: str) -> Path:
        q = (root / p).resolve()
        if root not in q.parents and q != root:
            raise ValueError("프로젝트 밖 경로는 읽을 수 없습니다")
        return q

    @function_tool
    def list_files(pattern: str) -> str:
        """프로젝트 안에서 glob 패턴에 맞는 파일 목록을 돌려준다. 예: '**/*.yml', '**/build.gradle'"""
        trace.append(f"list_files({pattern})")
        files = [p.relative_to(root).as_posix() for p in root.glob(pattern)
                 if p.is_file() and "/build/" not in p.as_posix()]
        return "\n".join(sorted(files)[:100]) or "(없음)"

    @function_tool
    def search_code(regex: str) -> str:
        """소스·설정·빌드 파일에서 정규식에 맞는 줄을 '경로:줄번호: 내용' 형식으로 최대 40개 돌려준다."""
        trace.append(f"search_code({regex})")
        try:
            pat = re.compile(regex)
        except re.error as e:
            return f"정규식 오류: {e}"
        hits = []
        for p in sorted(root.rglob("*")):
            if not p.is_file() or "/build/" in p.as_posix() or "/.git/" in p.as_posix():
                continue
            if p.suffix not in {".java", ".kt", ".yml", ".yaml", ".properties", ".xml", ".gradle", ".kts"}:
                continue
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if pat.search(line):
                    hits.append(f"{p.relative_to(root).as_posix()}:{n}: {line.strip()}")
                    if len(hits) >= 40:
                        return "\n".join(hits)
        return "\n".join(hits) or "(일치 없음)"

    @function_tool
    def read_file(path: str, start_line: int = 1, end_line: int = 80) -> str:
        """파일의 일부를 줄 번호와 함께 읽는다. 한 번에 최대 120줄."""
        trace.append(f"read_file({path}:{start_line}-{end_line})")
        try:
            lines = _safe(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:  # 없는 파일 등은 에이전트에게 그대로 알려 준다
            return f"읽기 실패: {e}"
        end_line = min(end_line, start_line + MAX_READ_LINES - 1, len(lines))
        return "\n".join(f"{i}: {lines[i - 1]}" for i in range(max(1, start_line), end_line + 1))

    return Agent(
        name="공급망 취약점 판정",
        instructions=INSTRUCTIONS,
        tools=[list_files, search_code, read_file],
        output_type=AgentDecision,
        model=model or os.environ.get("OPENAI_MODEL", "gpt-5-mini"),
    )


def _payload(f: Finding) -> str:
    return json.dumps({
        "key": f.key,
        "취약점": f.vuln_id,
        "다른_식별자": f.aliases,
        "라이브러리": f"{f.group}:{f.package}@{f.version}",
        "심각도": f.severity,
        "CVSS": f.cvss,
        "EPSS": f.epss,
        "EPSS_백분위": f.epss_percentile,
        "KEV_등재": f.in_kev,
        "수정_버전": f.fixed_versions,
        "설명": f.description,
        "직접_사용_위치": f.direct_usages,
        "규칙_판정": f.rule_tier.value if f.rule_tier else None,
        "규칙_근거": f.rule_reasons,
    }, ensure_ascii=False, indent=2)


def _usage(context_wrapper) -> dict | None:
    u = getattr(context_wrapper, "usage", None)
    if u is None:
        return None
    return {"requests": u.requests, "input_tokens": u.input_tokens,
            "output_tokens": u.output_tokens, "total_tokens": u.total_tokens}


async def _judge_one(f: Finding, src_root: str, sem: asyncio.Semaphore, model: str | None):
    """(판정, 도구 호출 기록, 오류, {"seconds", "usage"}) 를 돌려준다."""
    trace: list[str] = []
    async with sem:
        agent = build_agent(src_root, trace, model)
        t0 = time.perf_counter()
        try:
            res = await Runner.run(agent, _payload(f), max_turns=12)
            d: AgentDecision = res.final_output
            d.key = f.key  # 모델이 키를 바꿔 적는 실수 방지
            stats = {"seconds": round(time.perf_counter() - t0, 2), "usage": _usage(res.context_wrapper)}
            return d, trace, None, stats
        except Exception as e:  # 실패하면 규칙 판정을 유지하고 사유를 남긴다
            run_data = getattr(e, "run_data", None)  # 최대 턴 초과 등은 실패 직전까지의 사용량이 붙어 있다
            stats = {"seconds": round(time.perf_counter() - t0, 2),
                     "usage": _usage(getattr(run_data, "context_wrapper", None))}
            return None, trace, f"{type(e).__name__}: {e}", stats


async def judge_all(findings: list[Finding], src_root: str, concurrency: int = 4, model: str | None = None):
    sem = asyncio.Semaphore(concurrency)
    return await asyncio.gather(*[_judge_one(f, src_root, sem, model) for f in findings])
