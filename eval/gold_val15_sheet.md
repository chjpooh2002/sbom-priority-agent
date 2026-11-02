# 정답 작성용 사실 표

## 판정 기준 (README 에서 그대로 읽어 옴)

판정은 라이브러리 단위가 아니라 취약점 단위로 한다. 아래 질문을 순서대로 묻고, 처음 "아니오"가 나온 곳에서 등급을 정한다.

1. 실행 중 로드되는가: 우리 코드든 프레임워크든, 서비스가 실행될 때 이 라이브러리의 코드가 실제로 쓰이는가.
2. 취약한 기능이 켜져 있는가: 취약점이 있는 그 기능 자체를 쓰거나 켜 두었고, 취약점 설명에 적힌 공격 전제 조건(설정, 실행 환경, 배포 형태)이 이 서비스에서 성립하는가.
3. 외부 입력이 닿는가: 외부 요청 값이 그 취약한 기능까지 흘러가는가.
4. 쉽게 터지는가: 실제 악용 목록(KEV)에 있거나, 인증 없이 원격에서 쉽게 악용할 수 있는가.

| 결과 | 등급 | 조치 |
| --- | --- | --- |
| 1 이 아니오 | P4 낮음 | 기록만 |
| 2 또는 3 이 아니오 | P3 보통 | 정기 업데이트 때 |
| 4 가 아니오 | P2 높음 | 다음 배포에 포함 |
| 모두 예 | P1 긴급 | 이번 주 조치 |

"라이브러리가 요청 경로에 있다"는 2 의 근거가 아니다. 2 는 취약한 기능 자체가 쓰이는지를 묻는다.
- 예: Jetty 서버가 모든 요청을 받더라도, 특정 커넥터 기능의 취약점은 그 커넥터 기능을 켰을 때만 2 가 "예"다.
- 예: XStream 이 클래스패스에 있어도, 외부에서 받은 XML 을 객체로 바꾸는 기능에 넣을 때만 2 가 "예"다.

"우리 코드가 직접 가져다 쓰지 않음"은 1 의 "아니오"가 아니다. 프레임워크가 내부에서 쓰면 1 은 "예"다.
1 을 "아니오"로 하려면 실행 중 로드되지 않는다는 근거(실행 파일에 없음, 해당 기능을 켜는 설정이 없음 등)가 있어야 한다.

## 이 표에 대해

대상: `eval/gold_val15.csv` 15건, 라이브러리 15종. 정답은 `eval/gold_val15.csv` 의 gold_tier 칸에 적는다.

판정 결과는 이 표에 넣지 않는다. 라이브러리 이름순, 라이브러리 안에서는 key 이름순으로 정렬했다.

"직접 사용 위치"는 `reach.py` 결과다(방식: `jar-index:sample-app/build/libs/sample-app-0.0.1.jar`). jar 색인 방식은 import 한 클래스가 실제로 들어 있는 라이브러리에만 연결하므로, 프레임워크를 거쳐 간접으로 쓰이는 경우는 "없음"으로 나온다. 실제 사용 방식은 라이브러리별 요약을 함께 본다.

- 스캔: 2026-11-02T10:26:30.9503357+09:00 · syft 1.54.1 · grype 0.121.0 · grype DB 2026-11-01T06:20:12Z
- KEV 2026.10.30 · EPSS 기준일 2026-11-01

## commons-collections 3.2.1 (1건)

**이 서비스에서 쓰이는 방식**

- build.gradle:18 에서 직접 선언(3.2.1).
- 코드에서 org.apache.commons.collections 를 가져오는 곳이 없고, ObjectInputStream 등 자바 직렬화를 쓰는 코드도 없다.

### `CVE-2015-7501|commons-collections`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2015-7501 | GHSA-fjq5-5j5f-mvxh | 9.8 | 0.8556 (백분위 99.7%) | 미등재 | 3.2.2 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Red Hat JBoss A-MQ 6.x; BPM Suite (BPMS) 6.x; BRMS 6.x and 5.x; Data Grid (JDG) 6.x; Data Virtualization (JDV) 6.x and 5.x; Enterprise Application Platform 6.x, 5.x, and 4.3.x; Fuse 6.x; Fuse Service Works (FSW) 6.x; Operations Network (JBoss ON) 3.x; Portal 6.x; SOA Platform (SOA-P) 5.x; Web Server

## h2 1.4.200 (1건)

**이 서비스에서 쓰이는 방식**

- build.gradle:19 에서 runtimeOnly 로 선언(1.4.200). 코드에서 org.h2 를 가져오는 곳은 없다.
- application.yml:2-4 에서 spring.h2.console.enabled=false 로 설정돼 있다. datasource 설정이 없고, 클래스패스에 spring-jdbc 가 없다.

### `CVE-2021-42392|h2`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-42392 | GHSA-h376-j262-vhq6 | 9.8 | 0.8318 (백분위 99.7%) | 미등재 | 2.0.206 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): The org.h2.util.JdbcUtils.getConnection method of the H2 database takes as parameters the class name of the driver and URL of the database. An attacker may pass a JNDI driver name and a URL leading to a LDAP or RMI servers, causing remote code execution. This can be exploited through various attack

## jackson-core 2.13.2 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-json 을 거쳐 들어온 간접 의존성이다(2.13.2). 코드에서 직접 가져오는 곳은 없다.
- 컨트롤러에 JSON 요청 본문을 받는 엔드포인트(@RequestBody)는 없다.

### `CVE-2026-68494|jackson-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2026-68494 | GHSA-r7wm-3cxj-wff9 | 8.7 | 0.0046 (백분위 40.2%) | 미등재 | 2.18.8 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): The fix released in jackson-core 2.18.6 and 2.21.1 for CVE-2026-18401 (GHSA-72hv-8253-57qq, number length constraint bypass in the non-blocking parser) is incomplete. This record covers the remaining bypass.  The earlier fix wired validateIntegerLength() into a new _setIntLength() helper and invoked

## jackson-databind 2.13.2 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-json 을 거쳐 들어온 간접 의존성이다(2.13.2). 코드에서 직접 가져오는 곳은 없다.
- 컨트롤러의 세 엔드포인트는 모두 GET 이고 String 을 반환한다. @RequestBody 와 ObjectMapper 설정(default typing 등)은 없다.

### `CVE-2022-42004|jackson-databind`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2022-42004 | GHSA-rgv9-q543-rqg4 | 8.2 | 0.0341 (백분위 88.9%) | 미등재 | 2.13.4 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): In FasterXML jackson-databind before 2.13.4, resource exhaustion can occur because of a lack of a check in BeanDeserializer._deserializeFromArray to prevent use of deeply nested arrays. An application is vulnerable only with certain customized choices for deserialization.

## log4j-core 2.14.1 (1건)

**이 서비스에서 쓰이는 방식**

- build.gradle:15 에서 직접 선언(2.14.1).
- GreetingController.java:4-5,15 에서 log4j-api 의 LogManager/Logger 를 가져오고, :18-19 에서 /hello 요청의 User-Agent 헤더 값을 log.info 의 인자로 기록한다.
- 실행 클래스패스에는 spring-boot-starter-logging 을 거쳐 들어온 log4j-to-slf4j 2.17.2 와 logback-classic 1.2.11 도 함께 있다. 저장소에 log4j2 설정 파일은 없다. LogManager 가 log4j-core 와 log4j-to-slf4j 중 어느 구현에 연결되는지는 저장소 파일만으로는 확인되지 않는다.

### `CVE-2025-68161|log4j-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2025-68161 | GHSA-vc5p-v9hr-52mj | 6.3 | 0.0077 (백분위 55.5%) | 미등재 | 2.25.3 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): The Socket Appender in Apache Log4j Core versions 2.0-beta9 through 2.25.2 does not perform TLS hostname verification of the peer certificate, even when the  verifyHostName https://logging.apache.org/log4j/2.x/manual/appenders/network.html#SslConfiguration-attr-verifyHostName  configuration attribut

## logback-core 1.2.11 (1건)

**이 서비스에서 쓰이는 방식**

- logback-classic 을 거쳐 들어온 간접 의존성이다(1.2.11).
- 저장소에 logback 설정 파일이 없다. 코드에서 직접 가져오는 곳은 없다.

### `CVE-2025-11226|logback-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2025-11226 | GHSA-25qh-j22f-pwp8 | 5.9 | 0.0019 (백분위 9.1%) | 미등재 | 1.3.16 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): ACE vulnerability in conditional configuration file processing  by QOS.CH logback-core up to and including version 1.5.18 in Java applications, allows an attacker to execute arbitrary code by compromising an existing logback configuration file or by injecting an environment variable before program e

## snakeyaml 1.29 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter 를 거쳐 들어온 간접 의존성이다(1.29). 코드에서 직접 가져오는 곳은 없다.
- Spring Boot 가 시작할 때 src/main/resources/application.yml 을 읽는 데 쓴다. 코드에는 요청으로 YAML 을 받거나 파싱하는 곳이 없다.

### `CVE-2022-38752|snakeyaml`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2022-38752 | GHSA-9w3m-gqgf-c4p9 | 6.5 | 0.0270 (백분위 85.9%) | 미등재 | 1.32 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stack-overflow.

## spring-beans 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter 를 거쳐 들어온 간접 의존성이다(5.3.17). 코드에서 직접 가져오는 곳은 없다.
- /profile 의 @ModelAttribute 바인딩(GreetingController.java:29)에 프레임워크의 데이터 바인딩이 쓰인다. bootJar 로 패키징하고(WAR 아님), build.gradle:9 은 sourceCompatibility 11, 이 저장소의 빌드와 스캔은 JDK 17 로 했다.

### `CVE-2022-22970|spring-beans`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2022-22970 | GHSA-hh26-6xwr-ggv7 | 7.5 | 0.0196 (백분위 80.3%) | 미등재 | 5.3.20 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): In spring framework versions prior to 5.3.20+ , 5.2.22+ and old unsupported versions, applications that handle file uploads are vulnerable to DoS attack if they rely on data binding to set a MultipartFile or javax.servlet.Part to a field in a model object.

## spring-boot 2.6.5 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 을 거쳐 들어온 간접 의존성이다(2.6.5).
- DemoApplication.java:3,9 에서 SpringApplication.run 으로 구동한다. actuator 는 의존성에 없다.

### `CVE-2025-22235|spring-boot`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2025-22235 | GHSA-rc42-6c7j-7h5r | 7.3 | 0.0044 (백분위 38.3%) | 미등재 | - | 예 |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/DemoApplication.java:3: import org.springframework.boot.SpringApplication;`
- 설명(앞 300자): EndpointRequest.to() creates a matcher for null/** if the actuator endpoint, for which the EndpointRequest has been created, is disabled or not exposed.  Your application may be affected by this if all the following conditions are met:    *  You use Spring Security   *  EndpointRequest.to() has been

## spring-context 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter 를 거쳐 들어온 간접 의존성이다(5.3.17). 코드에서 직접 가져오는 곳은 없다.
- 애플리케이션 컨텍스트 구동에 쓰인다(DemoApplication.java:9).

### `CVE-2025-22233|spring-context`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2025-22233 | GHSA-4wp7-92pw-q264 | 3.1 | 0.0043 (백분위 37.8%) | 미등재 | - | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): CVE-2024-38820 ensured Locale-independent, lowercase conversion for both the configured disallowedFields patterns and for request parameter names. However, there are still cases where it is possible to bypass the disallowedFields checks.  Affected Spring Products and Versions  Spring Framework:   *

## spring-core 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot 를 거쳐 들어온 간접 의존성이다(5.3.17). 코드에서 직접 가져오는 곳은 없다.
- 모든 Spring 모듈의 기반이다.

### `CVE-2025-41249|spring-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2025-41249 | GHSA-jmp9-x22r-554x | 7.5 | 0.0048 (백분위 41.3%) | 미등재 | - | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): The Spring Framework annotation detection mechanism may not correctly resolve annotations on methods within type hierarchies with a parameterized super type with unbounded generics. This can be an issue if such annotations are used for authorization decisions.  Your application may be affected by th

## spring-expression 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-context 와 spring-webmvc 를 거쳐 들어온 간접 의존성이다(5.3.17).
- 코드에서 SpEL(ExpressionParser, @Value 의 #{...})을 직접 쓰는 곳은 없다.

### `CVE-2026-41852|spring-expression`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2026-41852 | GHSA-9f52-rjqv-25qv | 3.7 | 0.0018 (백분위 7.3%) | 미등재 | - | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): A vulnerability in Spring Expression Language (SpEL) evaluation logic allows for arbitrary zero-argument method invocation, even within restricted or read-only contexts, which may allow an attacker to invoke unintended application logic.  Affected versions: Spring Framework 7.0.0 through 7.0.7; 6.2.

## spring-web 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 을 거쳐 들어온 간접 의존성이다(5.3.17).
- GreetingController.java:6-10 에서 org.springframework.web.bind.annotation 의 어노테이션(GetMapping, RequestParam, RequestHeader, ModelAttribute, RestController)을 가져온다.

### `CVE-2016-1000027|spring-web`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2016-1000027 | GHSA-4wrc-f8pq-fpqp | 9.8 | 0.3318 (백분위 98.4%) | 미등재 | 6.0.0 | 예 |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/GreetingController.java:6: import org.springframework.web.bind.annotation.GetMapping;`; `src/main/java/com/example/demo/GreetingController.java:7: import org.springframework.web.bind.annotation.ModelAttribute;`; `src/main/java/com/example/demo/GreetingController.java:8: import org.springframework.web.bind.annotation.RequestHeader;`; `src/main/java/com/example/demo/GreetingController.java:9: import org.springframework.web.bind.annotation.RequestParam;`; `src/main/java/com/example/demo/GreetingController.java:10: import org.springframework.web.bind.annotation.RestController;`
- 설명(앞 300자): Pivotal Spring Framework through 5.3.16 suffers from a potential remote code execution (RCE) issue if used for Java deserialization of untrusted data. Depending on how the library is implemented within a product, this issue may or not occur, and authentication may be required. NOTE: the vendor's pos

## spring-webmvc 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 을 거쳐 들어온 간접 의존성이다(5.3.17). GreetingController 의 @RestController 가 /hello, /template, /profile(모두 GET)을 처리한다.
- /profile 은 요청 값을 @ModelAttribute 로 Profile 객체에 바인딩한다(GreetingController.java:28-30). 정적 리소스 설정과 뷰 템플릿은 없다.

### `CVE-2026-22741|spring-webmvc`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2026-22741 | GHSA-wg35-8jpf-2xv3 | 3.1 | 0.0024 (백분위 14.6%) | 미등재 | - | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Spring MVC and WebFlux applications are vulnerable to cache poisoning when resolving static resources.   More precisely, an application can be vulnerable when all the following are true:    *  the application is using Spring MVC or Spring WebFlux   *  the application is configuring the  resource cha

## tomcat-embed-core 9.0.60 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 에서 spring-boot-starter-tomcat 을 거쳐 들어온 내장 서버다(9.0.60). bootJar(실행형 jar)로 패키징한다.
- 모든 HTTP 요청을 받는다(application.yml:6, server.port 8080). 그 밖의 Tomcat 설정(커넥터, AJP, 세션 저장 등)은 저장소에 없다.

### `CVE-2024-24549|tomcat-embed-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 | 실행 jar 포함 |
| --- | --- | --- | --- | --- | --- | --- |
| CVE-2024-24549 | GHSA-7w75-32cg-r6g2 | 7.5 | 0.2307 (백분위 97.8%) | 미등재 | 9.0.86 | 예 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Denial of Service due to improper input validation vulnerability for HTTP/2 requests in Apache Tomcat. When processing an HTTP/2 request, if the request exceeded any of the configured limits for headers, the associated HTTP/2 stream was not reset until after all of the headers had been processed.Thi
