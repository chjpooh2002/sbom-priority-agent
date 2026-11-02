# 사실 확인 기록

정답 판단에 쓸 사실만 적는다. 판정 등급과 순위는 적지 않는다.

- 대상: `sample-app/build/libs/sample-app-0.0.1.jar` (2026-11-02 15:11 빌드, 소스 마지막 변경 커밋과 같은 시각)
- 실행 환경: Temurin OpenJDK 21.0.10, Windows 11
- 실행 명령(두 확인 공통, 같은 프로세스에서 진행):

```
java -Xlog:class+load=info:file=classload.log -Dlog4j2.debug=true \
     -jar build/libs/sample-app-0.0.1.jar --server.port=18080
```

  - `-Xlog:class+load`: 로드된 클래스와 해당 jar를 기록한다. 어떤 코드가 실제로 실행됐는지 확인하는 근거로 쓴다.
  - `-Dlog4j2.debug=true`: log4j-api가 어떤 제공자(LoggerContextFactory)를 골랐는지 출력한다.
- 확인이 끝난 뒤 프로세스를 종료했고, 18080 포트가 비었음을 확인했다.

---

## 1. log4j: 컨트롤러의 `LogManager.getLogger` 호출은 어디서 처리되는가

### 배경
실행 jar의 `BOOT-INF/lib`에 log4j 관련 jar가 함께 들어 있다.

| jar | 역할 |
|---|---|
| `log4j-api-2.14.1.jar` | API (`LogManager`, `Logger`) |
| `log4j-core-2.14.1.jar` | log4j 자체 구현 (lookup, JNDI 처리 포함) |
| `log4j-to-slf4j-2.17.2.jar` | log4j API 호출을 SLF4J(logback)로 넘기는 연결 jar (spring-boot-starter-logging이 끌고 옴) |
| `logback-classic-1.2.11.jar` | 실제 로그 기록 |

어느 쪽이 쓰일지는 log4j-api가 시작할 때 각 제공자의 가중치(Weighting)를 비교해 정한다.

### 결과 1-a: 시작할 때 선택된 제공자 (`-Dlog4j2.debug=true` 출력)

```
Factory: org.apache.logging.log4j.core.impl.Log4jContextFactory, Weighting: 10
Factory: org.apache.logging.slf4j.SLF4JLoggerContextFactory, Weighting: 15
Using factory: org.apache.logging.slf4j.SLF4JLoggerContextFactory
```

가중치가 높은 log4j-to-slf4j(15)가 선택됐다.

### 결과 1-b: 로드된 클래스 (`-Xlog:class+load`)

- 로드됨: `org.apache.logging.slf4j.SLF4JLoggerContext`, `org.apache.logging.slf4j.SLF4JLogger`
  (출처는 둘 다 `BOOT-INF/lib/log4j-to-slf4j-2.17.2.jar`)
- log4j-core에서 로드된 클래스는 13개다. 모두 제공자를 비교하는 단계에서 만들어지는 팩토리·선택기 계열이다.
  `Log4jContextFactory`, `Log4jProvider`, `ClassLoaderContextSelector`, `DefaultShutdownCallbackRegistry`,
  `ShutdownCallbackRegistry`, `LifeCycle`, `LifeCycle2`, `LifeCycle$State`, `Filterable`, `Configuration`(인터페이스),
  `ContextSelector`, `Loader`, `Cancellable`
- 로드되지 않음: `org.apache.logging.log4j.core.LoggerContext`, `org.apache.logging.log4j.core.Logger`,
  `org.apache.logging.log4j.core.lookup.*`(JNDI lookup 포함). 아래 `/hello` 요청 두 번을 보낸 뒤에도 그대로였다.

### 결과 1-c: `/hello` 호출 후 기록 확인

```
curl -A "factcheck-marker-ua" http://localhost:18080/hello
→ 2026-11-03 01:07:08.710  INFO 64920 --- [io-18080-exec-1] com.example.demo.GreetingController      : hello called by factcheck-marker-ua
```

INFO 줄이 Spring Boot의 logback 기본 형식으로 찍혔다. log4j-core가 처리했다면, 설정 파일이 없을 때의 기본 설정은 ERROR 이상만 출력하므로 이 INFO 줄은 나오지 않았어야 한다.

lookup이 동작하는지는 해롭지 않은 로컬 lookup(`${java:version}`, 외부 접속 없음)으로 확인했다.

```
curl -A 'lookup-test ${java:version}' http://localhost:18080/hello
→ ... GreetingController      : hello called by lookup-test ${java:version}
```

문자열이 그대로 기록됐다. log4j-core의 메시지 lookup 치환은 일어나지 않았다.

### 결론 1
이 실행 jar를 `java -jar`로 띄웠을 때, 컨트롤러의 log4j API 호출은 log4j-to-slf4j를 거쳐 logback이 처리한다. log4j-core 2.14.1은 jar 안에 있지만 로거로 쓰이지 않고, lookup 치환도 일어나지 않았다.

전제: 이 결과는 선택된 제공자에 따라 달라진다. 실행 환경에서 `log4j2.loggerContextFactory` 속성을 지정하거나, 의존성이 바뀌어 log4j-to-slf4j가 빠지면(예: spring-boot-starter-log4j2로 교체) log4j-core가 쓰이게 된다. 지금 빌드와 지금 실행 명령에서는 그런 설정이 없다.

---

## 2. commons-lang3: `/template` → `StringSubstitutor` → `ClassUtils.getClass` 경로가 성립하는가

### 배경
- 컨트롤러 코드: `StringSubstitutor.createInterpolator().replace(text)`. 여기서 `text`는 요청 파라미터이고, 사용자가 그대로 넣을 수 있다.
- jar 안의 `commons-text-1.9.jar` 바이트코드를 `javap -c`로 확인했다. commons-text 1.9에서 `org/apache/commons/lang3/ClassUtils`를 참조하는 클래스는 `org.apache.commons.text.lookup.ConstantStringLookup` 하나뿐이다. 호출 흐름은 `lookup` → `resolveField` → `fetchClass` → `ClassUtils.getClass(String)`이다.
- 따라서 `${const:클래스명.필드명}` 입력이 들어오면, 사용자가 넣은 클래스명으로 `ClassUtils.getClass`가 호출되는지를 보면 된다.

### 입력
해롭지 않은 입력을 골랐다. JDK 공개 상수를 읽기만 하고, 외부 접속, 스크립트 실행, 긴 문자열이 없다.

| 요청 | 응답 | 이 요청 뒤 새로 로드된 관련 클래스 |
|---|---|---|
| `text=plain-text` (대조군) | `plain-text` | `org.apache.commons.text.StringSubstitutor`, `org.apache.commons.text.lookup.ConstantStringLookup` |
| `text=${const:java.lang.Integer.MAX_VALUE}` | `2147483647` | `org.apache.commons.lang3.ClassUtils` (출처 `BOOT-INF/lib/commons-lang3-3.12.0.jar`) |

- 대조군 요청에서는 `createInterpolator()`가 조회기를 등록하므로 `ConstantStringLookup`까지는 로드되지만, `ClassUtils`는 로드되지 않았다.
- const 요청을 보내자 `ClassUtils`가 처음 로드됐다. 응답 값 `2147483647`은 `java.lang.Integer` 클래스를 찾아 필드를 읽어야만 나올 수 있다.

### 결론 2
이 경로는 실제로 성립한다. 인증 없는 GET `/template?text=${const:...}` 요청으로 사용자가 넣은 클래스명이 commons-lang3 3.12.0의 `ClassUtils.getClass(String)`에 전달된다.

한계: 이번 확인은 "그 함수까지 도달하는가"만 본 것이다. 취약점 자체(긴 클래스명 입력에서의 재귀 호출)는 서비스 장애를 일으킬 수 있는 입력이라 의도적으로 실행하지 않았다. 그 입력이 실제로 스택 넘침까지 가는지는 확인하지 않았다.
