#!/usr/bin/env bash
# 분석 대상 프로젝트를 빌드하고, 구성 요소 목록(SBOM)과 취약점 스캔 결과를 만든다.
# 필요: JDK 17, syft, grype   (맥: brew install syft grype)
set -euo pipefail

# 0) 예제 서비스(Spring Boot 2.6.5, Gradle 7.6.4)는 JDK 17에서만 빌드를 보장한다.
#    gradlew 와 같은 순서(JAVA_HOME 우선, 없으면 PATH)로 실제 쓰일 java 를 확인한다.
if [ -n "${JAVA_HOME:-}" ]; then JAVA_BIN="$JAVA_HOME/bin/java"; else JAVA_BIN="java"; fi
JAVA_MAJOR=$("$JAVA_BIN" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1 || true)
if [ "$JAVA_MAJOR" != "17" ]; then
  echo "JDK 17이 필요합니다. JAVA_HOME을 JDK 17 경로로 지정하세요 (현재: ${JAVA_MAJOR:-확인 불가})" >&2
  exit 1
fi

APP_DIR="${1:-sample-app}"
OUT_DIR="${2:-out}"
mkdir -p "$OUT_DIR"

# 1) 실행 파일(jar)로 빌드해야 간접 의존성까지 전부 잡힌다
if [ -x "$APP_DIR/gradlew" ]; then
  (cd "$APP_DIR" && ./gradlew -q bootJar)
else
  (cd "$APP_DIR" && gradle -q bootJar)
fi
JAR=$(ls "$APP_DIR"/build/libs/*.jar | grep -v plain | head -1)

# 2) 구성 요소 목록 (CycloneDX 형식)
syft "$JAR" -o cyclonedx-json > "$OUT_DIR/sbom.cdx.json"

# 3) 구성 요소 목록 기준 취약점 스캔
grype "sbom:$OUT_DIR/sbom.cdx.json" -o json > "$OUT_DIR/grype.json"

echo "완료: $OUT_DIR/sbom.cdx.json, $OUT_DIR/grype.json"
