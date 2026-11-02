"""규칙 기반 1차 우선순위. 숫자로 판단할 수 있는 부분은 언어 모델에 맡기지 않는다."""
from __future__ import annotations

from .models import Finding, Tier

EPSS_HIGH = 0.10   # 30일 안에 악용될 확률 10% 이상
CVSS_HIGH = 7.0


def cvss_only_tier(f: Finding) -> Tier:
    """비교 기준선: 심각도 점수만 보는 흔한 방식."""
    s = f.cvss or 0
    if s >= 9.0:
        return Tier.P1
    if s >= 7.0:
        return Tier.P2
    if s >= 4.0:
        return Tier.P3
    return Tier.P4


def rule_tier(f: Finding) -> tuple[Tier, list[str]]:
    used = bool(f.direct_usages)
    cvss = f.cvss or 0
    epss = f.epss or 0
    r: list[str] = []
    if f.in_kev:
        r.append("실제 악용이 확인된 목록(KEV)에 있음")
    if epss >= EPSS_HIGH:
        r.append(f"악용 가능성 점수 {epss:.3f} (기준 {EPSS_HIGH} 이상)")
    if cvss >= CVSS_HIGH:
        r.append(f"심각도 {cvss}")
    r.append("우리 코드에서 직접 사용" if used else "우리 코드에서 직접 사용하지 않음")
    if not f.fixed_versions:
        r.append("수정 버전 없음")

    if f.in_kev and used:
        return Tier.P1, r
    if used and epss >= EPSS_HIGH and cvss >= CVSS_HIGH:
        return Tier.P1, r
    if f.in_kev or (used and cvss >= CVSS_HIGH) or epss >= EPSS_HIGH:
        return Tier.P2, r
    if used or cvss >= CVSS_HIGH:
        return Tier.P3, r
    # P4 는 "실행 중 로드되지 않음" 근거가 있을 때만 준다. 직접 쓰지 않아도 프레임워크가 쓸 수 있으므로
    # 실행 jar 에 들어 있거나 확인할 수 없으면 P3 을 하한으로 둔다(P4 로 내릴 근거 찾기는 에이전트 몫).
    if f.in_runtime is False:
        r.append("실행 jar 에 없음")
        return Tier.P4, r
    r.append("실행 jar 에 포함(로드 여부 미확인) → 최저 P3" if f.in_runtime else "실행 jar 확인 불가 → 최저 P3")
    return Tier.P3, r


def apply_rules(findings: list[Finding]) -> None:
    for f in findings:
        f.rule_tier, f.rule_reasons = rule_tier(f)
