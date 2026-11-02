# 1차 측정 오답 원인 분류

- 대상: `eval/gold30.csv` 30건. 에이전트는 gpt-6-luna(주 측정)와 gpt-6-sol(비교 측정)
- 근거·도구 호출·메모 원문: `eval/wrong_detail_gpt-6-luna.txt`, `eval/wrong_detail_gpt-6-sol.txt`
- 수정은 하지 않았다. 아래 수정안은 제안이다.

## 분류 결과

틀린 항목은 두 모델을 합쳐 26건이다(luna 25건, sol 22건, 겹치는 항목 21건).

| 원인 | 건수 | 해당 항목 |
| --- | --- | --- |
| 정답 기준 모호 | 11 | spring-web ×2, spring-webmvc ×2, tomcat-embed-core ×2, jackson-databind ×2, log4j-api, log4j-core(44832), spring-core |
| 규칙 문제 | 8 | snakeyaml ×2, logback-core ×2, spring-expression, spring-context, tomcat-embed-websocket, commons-lang3 |
| 에이전트 판단 문제 | 6 | spring-boot-autoconfigure, spring-boot, logback-classic(luna), jackson-core(luna), commons-collections(luna), h2(luna) |
| 도구 부족 | 1 | log4j-core 44228(sol) |

## 항목별

| key | 정답 | 규칙 | luna | sol | 원인 | 요지 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44228\|log4j-core | P1 | P2 | 정답 | P2 | 도구 부족 | 헤더가 `log.info`에 닿는 것은 확인했다. 하지만 log4j-core와 log4j-to-slf4j 중 무엇이 실제 로깅 구현인지 확인할 도구가 없어 P2에 머물렀다. |
| CVE-2021-44832\|log4j-core | P1 | P2 | P3 | P4 | 정답 기준 모호 | 공격자가 로깅 설정을 바꿀 수 있어야 하는 취약점이다. 메모의 근거는 44228과 같다(헤더가 로그에 기록됨). |
| CVE-2026-49844\|log4j-api | P1 | P3 | P4 | P4 | 정답 기준 모호 | MapMessage를 JSON으로 직렬화하는 기능이 전제다. 코드는 일반 매개변수 로그만 남긴다. |
| CVE-2024-22243\|spring-web | P1 | P2 | P4 | P4 | 정답 기준 모호 | UriComponentsBuilder로 리다이렉트하는 기능이 전제인데, 코드에서 쓰지 않는다. 메모는 "@RestController가 요청을 받는다"는 라이브러리 수준의 근거다. |
| CVE-2024-22262\|spring-web | P1 | P2 | P4 | P4 | 정답 기준 모호 | 위와 같다. |
| CVE-2024-38819\|spring-webmvc | P1 | P2 | P4 | P2 | 정답 기준 모호 | 함수형 라우팅(WebMvc.fn)의 정적 리소스 기능이 전제인데, 쓰지 않는다. |
| CVE-2026-41853\|spring-webmvc | P1 | P4 | P4 | P4 | 정답 기준 모호 | multipart 처리 취약점이다. 에이전트는 "multipart 핸들러가 없다"를 근거로 들었다. 그런데 Spring Boot 기본 설정에서는 DispatcherServlet이 핸들러와 상관없이 multipart 요청을 파싱할 수 있어, 이 근거는 부족할 수 있다(확인 필요). |
| CVE-2025-53506\|tomcat-embed-core | P1 | P3 | P4 | P4 | 정답 기준 모호 | HTTP/2 활성화가 전제인데, 기본값은 꺼져 있고 설정도 없다. README 기준으로는 P3이다. 에이전트의 P4도 기준보다 한 단계 낮다. |
| CVE-2025-55668\|tomcat-embed-core | P1 | P4 | P4 | P4 | 정답 기준 모호 | 세션 고정 취약점으로, rewrite valve 설정이 전제다. 메모는 "모든 요청을 받는다"이다. |
| CVE-2026-77310\|jackson-databind | P1 | P4 | P4 | P4 | 정답 기준 모호 | JSON을 InetAddress로 역직렬화하는 기능이 전제다. JSON 본문을 받는 엔드포인트가 없다. |
| CVE-2026-91776\|jackson-databind | P1 | P3 | P4 | P4 | 정답 기준 모호 | 다형성 역직렬화가 전제인데, 해당 설정과 JSON 본문 입력이 없다. |
| CVE-2026-41848\|spring-core | P2 | P4 | P4 | P4 | 정답 기준 모호 | AntPathMatcher 관련 취약점이다. Boot 2.6은 기본적으로 PathPatternParser를 쓰지만, 메모에는 경로가 없다. 에이전트의 P4는 프레임워크가 쓰는 라이브러리라 README 기준보다 낮다. |
| CVE-2022-38749\|snakeyaml | P3 | P4 | P4 | P4 | 규칙 문제 | 규칙이 "직접 사용 안 함"을 P4로 매겼고, 에이전트는 그대로 따랐다. 실제로는 Spring Boot가 application.yml을 읽을 때 쓰므로 README 기준 P3이다. |
| CVE-2022-38751\|snakeyaml | P3 | P4 | P4 | P4 | 규칙 문제 | 위와 같다. |
| CVE-2023-20861\|spring-expression | P3 | P4 | P4 | P4 | 규칙 문제 | 프레임워크 내부에서 쓰이므로 P3이 맞다. |
| CVE-2024-38820\|spring-context | P3 | P4 | P4 | P4 | 규칙 문제 | 위와 같다. |
| CVE-2024-12801\|logback-core | P3 | P4 | P4 | P4 | 규칙 문제 | 기본 로깅 구현이라 프레임워크가 쓴다. |
| CVE-2026-10532\|logback-core | P3 | P4 | P4 | P4 | 규칙 문제 | 위와 같다. |
| CVE-2024-23672\|tomcat-embed-websocket | P3 | P4 | P4 | P4 | 규칙 문제 | 내장 Tomcat이 시작할 때 불러온다. |
| CVE-2025-48924\|commons-lang3 | P3 | P4 | P4 | P4 | 규칙 문제 | commons-text가 쓴다. |
| CVE-2023-20883\|spring-boot-autoconfigure | P3 | P2 | P4 | P4 | 에이전트 판단 문제 | 규칙 판정에서 두 단계를 내렸다. 자동 설정 자체는 쓰이므로 P3이 하한이다. |
| CVE-2026-40973\|spring-boot | P2 | P2 | P3 | P4 | 에이전트 판단 문제 | sol은 두 단계를 내렸고, 근거에 "외부에 배포하지 않음" 주석이 들어 있다. |
| CVE-2023-6378\|logback-classic | P3 | P3 | P4 | 정답 | 에이전트 판단 문제 | luna가 프레임워크 사용 라이브러리를 P4로 내렸다. |
| CVE-2026-89425\|jackson-core | P3 | P3 | P4 | 정답 | 에이전트 판단 문제 | 위와 같다. |
| CVE-2015-6420\|commons-collections | P4 | P2 | P3 | 정답 | 에이전트 판단 문제 | 어디서도 쓰지 않는데, luna가 "프레임워크 내부를 다 확인하지 못했다"며 P3에 머물렀다. |
| CVE-2022-23221\|h2 | P4 | P2 | P3 | 정답 | 에이전트 판단 문제 | 데이터 소스와 spring-jdbc가 없어 로드되지 않는데, luna가 P3에 머물렀다. |

## 공통으로 보이는 문제

1. **정답 기준과 README 기준이 다르다.** 메모는 ①~④ 단계 중 어디서 멈췄는지로 등급을 정했다(④→P1, ③→P2, ②→P3, ①→P4). 그런데 이 단계 정의가 저장소에 없다. 또 P1 메모의 상당수는 라이브러리가 요청 경로에 있는지를 근거로 든다. 반면 README의 P1은 "외부 입력이 *취약 기능*에 닿는지"를 묻는다. 그래서 규칙도 에이전트도 같은 기준을 따를 수 없다.
2. **에이전트에 등급 정의가 없다.** 지시문은 "P1 긴급 … P4 낮음"이라는 이름만 주고, README의 P3/P4 경계("프레임워크에서도 쓰이지 않음")는 주지 않는다. 그래서 두 모델 모두 "경로 확인 안 됨"을 P4로 매겼다.
3. **"한 단계 조정"을 코드로 강제하지 않는다.** 지시문은 한 단계만 조정하라고 하지만, 규칙 P2를 P4로 내린 경우가 여러 건 있다(spring-web ×2, spring-boot-autoconfigure, spring-boot).
4. **측정용 주석이 근거로 쓰인다.** `build.gradle:1-2`의 "외부에 배포하지 않는다" 주석을 틀린 항목 근거에서 luna가 10번, sol이 13번 인용했다.

## 수정안 (적용하지 않음)

| 대상 | 수정안 | 일반 원칙인가 |
| --- | --- | --- |
| 정답 기준 | ①~④ 단계를 README에 적고, P1을 "라이브러리가 요청 경로에 있음"과 "취약 기능에 입력이 닿음" 중 어느 쪽으로 볼지 정한다. 기준을 바꾸면 30건 전체에 같은 기준을 다시 적용한다. 판정을 보고 개별 항목만 고치면 측정 오염이다. 바꾼 기준은 "정답 v2"로 기록하고, v1 측정과 함께 보고한다. | 사람의 판단 기준 문제라 일반 원칙과는 다른 차원이다 |
| 규칙 | "직접 사용 안 함"이면 P4 대신 P3을 하한으로 둔다. P4는 실행 클래스패스에 없거나 로드되지 않는다는 근거가 있을 때만 준다(에이전트 몫). | 그렇다. import가 없다고 쓰이지 않는 것은 아니다(README P4 정의와 같음) |
| 에이전트 지시문 | README의 P1~P4 정의를 그대로 넣는다. 배포 여부와 용도에 대한 코드 주석은 근거로 쓰지 말고, 인터넷에 노출된 서비스로 가정하게 한다. | 그렇다. 사람과 에이전트가 같은 등급 기준을 쓴다 |
| 에이전트 코드 | 최종 판정을 규칙 판정에서 ±1단계로 제한한다(지시문 내용을 코드로 강제). | 그렇다 |
| 도구 | 실행 jar의 실제 라이브러리 목록이나 SBOM을 읽는 읽기 전용 도구를 추가한다(로깅 구현 등 실제 런타임 구성 확인용). | 그렇다 |

**주의**: 위 수정안은 오답을 보고 만든 것이라, 같은 30건으로 다시 재면 낙관적인 수치가 나온다. 효과를 확인하려면 정답 대상이 아닌 102건에서 10~15건을 새로 골라 결과를 보기 전에 정답을 매기고, 그 세트로 검증하는 것이 맞다.
