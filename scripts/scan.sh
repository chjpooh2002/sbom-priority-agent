#!/usr/bin/env bash
# 분석 대상 프로젝트를 빌드하고, 구성 요소 목록(SBOM)과 취약점 스캔 결과를 만든다.
# 필요: JDK 11 이상, syft, grype   (맥: brew install syft grype)
set -euo pipefail

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
