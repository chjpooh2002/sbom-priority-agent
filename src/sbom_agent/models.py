from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Tier(str, Enum):
    P1 = "P1"  # 긴급: 이번 주 안에 조치
    P2 = "P2"  # 높음: 다음 배포에 포함
    P3 = "P3"  # 보통: 정기 업데이트 때
    P4 = "P4"  # 낮음: 기록만

    @property
    def rank(self) -> int:
        return int(self.value[1])


class Finding(BaseModel):
    """스캐너 결과 한 건 = (취약점, 패키지) 한 쌍."""

    key: str                       # 예: CVE-2021-44228|log4j-core
    vuln_id: str                   # 대표 식별자(CVE 우선)
    aliases: list[str] = []
    package: str
    version: str
    purl: str = ""
    group: str = ""                # 메이븐 그룹 아이디
    severity: str = "Unknown"
    cvss: Optional[float] = None
    fixed_versions: list[str] = []
    description: str = ""

    # 보강 데이터
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_kev: bool = False

    # 코드 사용 여부
    direct_usages: list[str] = []  # "경로:줄번호: 코드"
    in_runtime: Optional[bool] = None  # 실행 jar 안에 들어 있는가(jar 가 없어 확인 못 하면 None)

    # 판정
    rule_tier: Optional[Tier] = None
    rule_reasons: list[str] = []


class AgentDecision(BaseModel):
    """에이전트가 반드시 이 형식으로만 답하게 한다."""

    key: str = Field(description="판정 대상 Finding.key 그대로")
    tier: Tier = Field(description="최종 우선순위 P1~P4")
    changed_from_rule: bool = Field(description="규칙 판정과 다르면 true")
    exploit_path: str = Field(description="이 서비스에서 실제로 공격이 닿는 경로. 없으면 '확인된 경로 없음'")
    evidence: list[str] = Field(description="판단 근거. 파일 경로와 줄 번호, 외부 지표 값만 쓴다")
    remediation: str = Field(description="구체 조치: 올릴 버전, 수정할 파일, 임시 완화책")
    confidence: float = Field(ge=0, le=1, description="판단 확신도")
