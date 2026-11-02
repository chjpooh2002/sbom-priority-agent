"""코드 사용 여부: 취약한 라이브러리의 클래스를 우리 코드가 직접 가져다 쓰는가.

기본은 빌드된 실행 jar 색인 방식이다. jar 안의 라이브러리(BOOT-INF/lib, WEB-INF/lib)를 열어
"클래스 → 라이브러리 파일" 색인을 만들고, import 한 클래스를 실제로 가진 라이브러리에만 연결한다.
메이븐 그룹 아이디는 자바 패키지 이름과 다르고(org.springframework 는 spring-core·context·web 이 함께 씀),
API 와 구현이 패키지를 나눠 갖는 경우(log4j-api / log4j-core)도 있어 접두어만으로는 구분되지 않기 때문이다.
jar 가 없으면 예전처럼 패키지 접두어로 찾는다.

직접 쓰지 않아도 프레임워크가 내부에서 쓰는 경우(예: 스프링이 설정 파일을 읽을 때 쓰는 YAML 파서)는
여기서 잡히지 않는다. 그 판단은 에이전트가 설정 파일과 코드를 읽고 내린다.
"""
from __future__ import annotations

import io
import re
import zipfile
from collections import defaultdict
from pathlib import Path

from .models import Finding

# jar 가 없을 때 쓰는 접두어 방식: 메이븐 좌표의 그룹 아이디와 실제 자바 패키지 이름이 다른 경우만 적는다.
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
LIB_DIRS = ("BOOT-INF/lib/", "WEB-INF/lib/")
IMPORT = re.compile(r"^\s*import\s+(static\s+)?([\w.]+?)(\.\*)?\s*;?\s*$")


def _sources(root: Path):
    for g in SOURCE_GLOBS:
        for p in sorted(root.glob(g)):
            if "/build/" in p.as_posix() or "/test/" in p.as_posix():
                continue
            yield p


def find_boot_jar(src_root: str | Path) -> Path | None:
    """scan.sh 와 같은 규칙으로 실행 jar 를 찾는다(build/libs 의 plain 이 아닌 jar)."""
    jars = [p for p in sorted(Path(src_root).glob("build/libs/*.[jw]ar")) if "plain" not in p.name]
    return jars[0] if jars else None


class JarIndex:
    """실행 jar 안 라이브러리들의 클래스 색인."""

    def __init__(self, jar: Path):
        self.jar = jar
        self.classes: dict[str, str] = {}                     # org/x/Y → lib 파일 이름
        self.packages: dict[str, set[str]] = defaultdict(set)  # org/x → lib 파일 이름들
        with zipfile.ZipFile(jar) as z:
            for name in z.namelist():
                if not (name.startswith(LIB_DIRS) and name.endswith(".jar")):
                    continue
                lib = name.rsplit("/", 1)[1]
                with zipfile.ZipFile(io.BytesIO(z.read(name))) as inner:
                    for n in inner.namelist():
                        if n.endswith(".class") and not n.startswith(("META-INF/", "module-info")):
                            cls = n[:-6]
                            self.classes.setdefault(cls, lib)
                            self.packages[cls.rsplit("/", 1)[0]].add(lib)

    def libs_for_import(self, name: str, wildcard: bool) -> set[str]:
        path = name.replace(".", "/")
        if wildcard and path in self.packages:
            return set(self.packages[path])
        # 중첩 클래스·static 멤버 import 는 뒤에서부터 잘라 가며 실제 클래스를 찾는다
        while path:
            if path in self.classes:
                return {self.classes[path]}
            if "/" not in path:
                break
            path = path.rsplit("/", 1)[0]
        return set()


def _lib_matches(f: Finding, lib: str) -> bool:
    if lib == f"{f.package}-{f.version}.jar":
        return True
    rest = lib[len(f.package) + 1:] if lib.startswith(f.package + "-") else ""
    return bool(rest[:1].isdigit())  # 버전 표기가 스캐너와 조금 다른 경우


def _usages_by_jar(findings: list[Finding], root: Path, index: JarIndex, limit: int) -> None:
    hits: list[tuple[str, set[str]]] = []  # (표시 문자열, 연결된 lib)
    for p in _sources(root):
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            m = IMPORT.match(line)
            if m:
                libs = index.libs_for_import(m.group(2), bool(m.group(3)))
                if libs:
                    hits.append((f"{p.relative_to(root).as_posix()}:{n}: {line.strip()}", libs))
    for f in findings:
        f.direct_usages = [h for h, libs in hits if any(_lib_matches(f, lib) for lib in libs)][:limit]


def java_prefixes(f: Finding) -> list[str]:
    if f.package in PACKAGE_OVERRIDES:
        return PACKAGE_OVERRIDES[f.package]
    return [f.group] if f.group else []


def find_usages(f: Finding, src_root: str | Path, limit: int = 8) -> list[str]:
    """jar 가 없을 때 쓰는 접두어 방식."""
    root = Path(src_root)
    prefixes = java_prefixes(f)
    if not prefixes:
        return []
    pat = re.compile(r"^\s*import\s+(static\s+)?(" + "|".join(re.escape(p) for p in prefixes) + r")\.")
    hits: list[str] = []
    for p in _sources(root):
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if pat.search(line):
                hits.append(f"{p.relative_to(root).as_posix()}:{n}: {line.strip()}")
                if len(hits) >= limit:
                    return hits
    return hits


def annotate(findings: list[Finding], src_root: str | Path, jar: str | Path | None = None,
             limit: int = 8) -> str:
    """direct_usages 를 채우고, 쓴 방식을 돌려준다("jar-index:<경로>" 또는 "import-prefix")."""
    root = Path(src_root)
    jar_path = Path(jar) if jar else find_boot_jar(root)
    if jar_path and jar_path.is_file():
        _usages_by_jar(findings, root, JarIndex(jar_path), limit)
        return f"jar-index:{jar_path.as_posix()}"
    for f in findings:
        f.direct_usages = find_usages(f, root, limit)
    return "import-prefix"
