"""코드 사용 여부: 취약한 라이브러리의 자바 패키지를 우리 코드가 직접 가져다 쓰는가.

직접 쓰지 않아도 프레임워크가 내부에서 쓰는 경우(예: 스프링이 설정 파일을 읽을 때 쓰는 YAML 파서)는
여기서 잡히지 않는다. 그 판단은 에이전트가 설정 파일과 코드를 읽고 내린다.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import Finding

# 메이븐 좌표의 그룹 아이디와 실제 자바 패키지 이름이 다른 경우만 적는다.
PACKAGE_OVERRIDES: dict[str, list[str]] = {
    "jackson-databind": ["com.fasterxml.jackson.databind"],
    "jackson-core": ["com.fasterxml.jackson.core"],
    "snakeyaml": ["org.yaml.snakeyaml"],
    "commons-text": ["org.apache.commons.text"],
    "commons-lang3": ["org.apache.commons.lang3"],
    "commons-collections": ["org.apache.commons.collections"],
    "commons-collections4": ["org.apache.commons.collections4"],
    "log4j-core": ["org.apache.logging.log4j"],
    "log4j-api": ["org.apache.logging.log4j"],
    "spring-beans": ["org.springframework.beans"],
    "spring-web": ["org.springframework.web"],
    "spring-webmvc": ["org.springframework.web.servlet"],
    "h2": ["org.h2"],
    "guava": ["com.google.common"],
    "netty-codec-http": ["io.netty.handler.codec.http"],
}

SOURCE_GLOBS = ("**/*.java", "**/*.kt")


def java_prefixes(f: Finding) -> list[str]:
    if f.package in PACKAGE_OVERRIDES:
        return PACKAGE_OVERRIDES[f.package]
    return [f.group] if f.group else []


def find_usages(f: Finding, src_root: str | Path, limit: int = 8) -> list[str]:
    root = Path(src_root)
    prefixes = java_prefixes(f)
    if not prefixes:
        return []
    pat = re.compile(r"^\s*import\s+(static\s+)?(" + "|".join(re.escape(p) for p in prefixes) + r")\.")
    hits: list[str] = []
    for g in SOURCE_GLOBS:
        for p in sorted(root.glob(g)):
            if "/build/" in p.as_posix() or "/test/" in p.as_posix():
                continue
            for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if pat.search(line):
                    hits.append(f"{p.relative_to(root)}:{n}: {line.strip()}")
                    if len(hits) >= limit:
                        return hits
    return hits


def annotate(findings: list[Finding], src_root: str | Path) -> None:
    for f in findings:
        f.direct_usages = find_usages(f, src_root)
