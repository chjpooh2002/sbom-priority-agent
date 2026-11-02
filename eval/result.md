# 정확도 측정 결과

| 방식 | 건수 | 정확히 일치 | 한 단계 이내 | 급한 건 놓치지 않은 비율 | 불필요한 긴급 경보 건수 |
| --- | --- | --- | --- | --- | --- |
| 심각도 점수만 | 30 | 30% | 67% | 57% | 8 |
| 규칙 | 30 | 17% | 70% | 50% | 4 |
| 규칙 + 에이전트 (gpt-6-luna) | 30 | 17% | 63% | 14% | 0 |
| 규칙 + 에이전트 (gpt-6-sol) | 30 | 27% | 63% | 21% | 0 |

### 경보 감소 (전체 결과 기준)

전체 132건 중 P1·P2 로 남은 건수. 감소율은 '심각도 점수만' 대비. 에이전트는 정답 대상만 판정했으므로 나머지는 규칙 판정이 그대로 들어 있다.

| 방식 | P1·P2 건수 | 전체 대비 | 감소율 |
| --- | --- | --- | --- |
| 심각도 점수만 | 76 | 58% | 0% |
| 규칙 | 29 | 22% | 62% |
| 규칙 + 에이전트 (gpt-6-luna) | 20 | 15% | 74% |
| 규칙 + 에이전트 (gpt-6-sol) | 21 | 16% | 72% |

### 에이전트: gpt-6-luna

- 에이전트 판정 30건(성공 30, 실패 0), 실패율 0%
- 규칙 판정을 바꾼 건수: 16건 (성공 30건 중)
  - 채점 대상 중 바꾼 16건: 정답에 가까워짐 5 / 멀어짐 10 / 거리 같음 1
- 근거 검증률: 129/134 (96%) — evidence 의 '경로:줄번호'가 `sample-app` 안에 실제로 있는 비율. 경로 없는 근거 항목 37개
- 건당 평균 시간: 24.8초 (30건)
- 건당 평균 토큰: 8,607 (30건)
- 건당 평균 도구 호출: 7.9회
- 건당 평균 비용: $0.0016 (합계 $0.047, 100만 토큰당 입력 $0.1 / 출력 $0.5, 캐시 할인 미반영 상한)

### 에이전트: gpt-6-sol

- 에이전트 판정 30건(성공 30, 실패 0), 실패율 0%
- 규칙 판정을 바꾼 건수: 12건 (성공 30건 중)
  - 채점 대상 중 바꾼 12건: 정답에 가까워짐 4 / 멀어짐 7 / 거리 같음 1
- 근거 검증률: 126/126 (100%) — evidence 의 '경로:줄번호'가 `sample-app` 안에 실제로 있는 비율. 경로 없는 근거 항목 30개
- 건당 평균 시간: 16.5초 (30건)
- 건당 평균 토큰: 10,112 (30건)
- 건당 평균 도구 호출: 12.7회
- 건당 평균 비용: $0.0293 (합계 $0.880, 100만 토큰당 입력 $2.0 / 출력 $10.0, 캐시 할인 미반영 상한)

### 최종 판정이 틀린 항목: gpt-6-luna

- CVE-2015-6420|commons-collections: 정답 P4, 최종 P3, 규칙 P2
- CVE-2021-44832|log4j-core: 정답 P1, 최종 P3, 규칙 P2
- CVE-2022-23221|h2: 정답 P4, 최종 P3, 규칙 P2
- CVE-2022-38749|snakeyaml: 정답 P3, 최종 P4, 규칙 P4
- CVE-2022-38751|snakeyaml: 정답 P3, 최종 P4, 규칙 P4
- CVE-2023-20861|spring-expression: 정답 P3, 최종 P4, 규칙 P4
- CVE-2023-20883|spring-boot-autoconfigure: 정답 P3, 최종 P4, 규칙 P2
- CVE-2023-6378|logback-classic: 정답 P3, 최종 P4, 규칙 P3
- CVE-2024-12801|logback-core: 정답 P3, 최종 P4, 규칙 P4
- CVE-2024-22243|spring-web: 정답 P1, 최종 P4, 규칙 P2
- CVE-2024-22262|spring-web: 정답 P1, 최종 P4, 규칙 P2
- CVE-2024-23672|tomcat-embed-websocket: 정답 P3, 최종 P4, 규칙 P4
- CVE-2024-38819|spring-webmvc: 정답 P1, 최종 P4, 규칙 P2
- CVE-2024-38820|spring-context: 정답 P3, 최종 P4, 규칙 P4
- CVE-2025-48924|commons-lang3: 정답 P3, 최종 P4, 규칙 P4
- CVE-2025-53506|tomcat-embed-core: 정답 P1, 최종 P4, 규칙 P3
- CVE-2025-55668|tomcat-embed-core: 정답 P1, 최종 P4, 규칙 P4
- CVE-2026-10532|logback-core: 정답 P3, 최종 P4, 규칙 P4
- CVE-2026-40973|spring-boot: 정답 P2, 최종 P3, 규칙 P2
- CVE-2026-41848|spring-core: 정답 P2, 최종 P4, 규칙 P4
- CVE-2026-41853|spring-webmvc: 정답 P1, 최종 P4, 규칙 P4
- CVE-2026-49844|log4j-api: 정답 P1, 최종 P4, 규칙 P3
- CVE-2026-77310|jackson-databind: 정답 P1, 최종 P4, 규칙 P4
- CVE-2026-89425|jackson-core: 정답 P3, 최종 P4, 규칙 P3
- CVE-2026-91776|jackson-databind: 정답 P1, 최종 P4, 규칙 P3

### 최종 판정이 틀린 항목: gpt-6-sol

- CVE-2021-44228|log4j-core: 정답 P1, 최종 P2, 규칙 P2
- CVE-2021-44832|log4j-core: 정답 P1, 최종 P4, 규칙 P2
- CVE-2022-38749|snakeyaml: 정답 P3, 최종 P4, 규칙 P4
- CVE-2022-38751|snakeyaml: 정답 P3, 최종 P4, 규칙 P4
- CVE-2023-20861|spring-expression: 정답 P3, 최종 P4, 규칙 P4
- CVE-2023-20883|spring-boot-autoconfigure: 정답 P3, 최종 P4, 규칙 P2
- CVE-2024-12801|logback-core: 정답 P3, 최종 P4, 규칙 P4
- CVE-2024-22243|spring-web: 정답 P1, 최종 P4, 규칙 P2
- CVE-2024-22262|spring-web: 정답 P1, 최종 P4, 규칙 P2
- CVE-2024-23672|tomcat-embed-websocket: 정답 P3, 최종 P4, 규칙 P4
- CVE-2024-38819|spring-webmvc: 정답 P1, 최종 P2, 규칙 P2
- CVE-2024-38820|spring-context: 정답 P3, 최종 P4, 규칙 P4
- CVE-2025-48924|commons-lang3: 정답 P3, 최종 P4, 규칙 P4
- CVE-2025-53506|tomcat-embed-core: 정답 P1, 최종 P4, 규칙 P3
- CVE-2025-55668|tomcat-embed-core: 정답 P1, 최종 P4, 규칙 P4
- CVE-2026-10532|logback-core: 정답 P3, 최종 P4, 규칙 P4
- CVE-2026-40973|spring-boot: 정답 P2, 최종 P4, 규칙 P2
- CVE-2026-41848|spring-core: 정답 P2, 최종 P4, 규칙 P4
- CVE-2026-41853|spring-webmvc: 정답 P1, 최종 P4, 규칙 P4
- CVE-2026-49844|log4j-api: 정답 P1, 최종 P4, 규칙 P3
- CVE-2026-77310|jackson-databind: 정답 P1, 최종 P4, 규칙 P4
- CVE-2026-91776|jackson-databind: 정답 P1, 최종 P4, 규칙 P3
