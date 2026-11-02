# 정답 작성용 사실 표

대상: `eval/gold30.csv` 30건, 라이브러리 21종. 정답은 `eval/gold30.csv` 의 gold_tier 칸에 적는다.

판정 결과는 이 표에 넣지 않는다. 라이브러리 이름순, 라이브러리 안에서는 key 이름순으로 정렬했다.

"직접 사용 위치"는 `reach.py` 결과다(방식: `jar-index:sample-app/build/libs/sample-app-0.0.1.jar`). jar 색인 방식은 import 한 클래스가 실제로 들어 있는 라이브러리에만 연결하므로, 프레임워크를 거쳐 간접으로 쓰이는 경우는 "없음"으로 나온다. 실제 사용 방식은 라이브러리별 요약을 함께 본다.

- 스캔: 2026-11-02T10:26:30.9503357+09:00 · syft 1.54.1 · grype 0.121.0 · grype DB 2026-11-01T06:20:12Z
- KEV 2026.10.30 · EPSS 기준일 2026-11-01

## 정답 기준 (README)

| 등급 | 기준 |
| --- | --- |
| P1 긴급 | 외부 입력이 취약 기능에 닿고, 실제 악용 사례가 있거나 악용이 쉬움. 이번 주 조치 |
| P2 높음 | 공격 경로가 있으나 조건이 붙음. 다음 배포에 포함 |
| P3 보통 | 경로가 확인되지 않거나 전제 조건이 성립하지 않음. 정기 업데이트 때 |
| P4 낮음 | 코드와 프레임워크 어디서도 쓰이지 않음. 기록만 |

## commons-collections 3.2.1 (1건)

**이 서비스에서 쓰이는 방식**

- build.gradle:20 에서 직접 선언(3.2.1).
- 코드에서 org.apache.commons.collections 를 가져오는 곳이 없고, ObjectInputStream 등 자바 직렬화를 쓰는 코드도 없다.

### `CVE-2015-6420|commons-collections`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2015-6420 | GHSA-6hgm-866r-3cjv | 9.8 | 0.1520 (백분위 96.8%) | 미등재 | 3.2.2 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Serialized-object interfaces in certain Cisco Collaboration and Social Media; Endpoint Clients and Client Software; Network Application, Service, and Acceleration; Network and Content Security Devices; Network Management and Provisioning; Routing and Switching - Enterprise and Service Provider; Unif

## commons-lang3 3.12.0 (1건)

**이 서비스에서 쓰이는 방식**

- commons-text 1.9 의 간접 의존성이다(3.11 이 요청되고 3.12.0 으로 해석).
- 코드에서 org.apache.commons.lang3 를 가져오는 곳은 없다.

### `CVE-2025-48924|commons-lang3`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2025-48924 | GHSA-j288-q9x7-2f5v | 6.5 | 0.0263 (백분위 85.5%) | 미등재 | 3.18.0 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Uncontrolled Recursion vulnerability in Apache Commons Lang.  This issue affects Apache Commons Lang: Starting with commons-lang:commons-lang 2.0 to 2.6, and, from org.apache.commons:commons-lang3 3.0 before 3.18.0.  The methods ClassUtils.getClass(...) can throw StackOverflowError on very long inpu

## commons-text 1.9 (1건)

**이 서비스에서 쓰이는 방식**

- build.gradle:19 에서 직접 선언(1.9).
- GreetingController.java:25-27 에서 /template 의 요청 파라미터 text 를 StringSubstitutor.createInterpolator().replace() 에 그대로 넘긴다.

### `CVE-2022-42889|commons-text`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2022-42889 | GHSA-599f-7c49-w659 | 9.8 | 0.9993 (백분위 100.0%) | 미등재 | 1.10.0 |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/GreetingController.java:3: import org.apache.commons.text.StringSubstitutor;`
- 설명(앞 300자): Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is "${prefix:name}", where "prefix" is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. S

## h2 1.4.200 (2건)

**이 서비스에서 쓰이는 방식**

- build.gradle:21 에서 runtimeOnly 로 선언(1.4.200). 코드에서 org.h2 를 가져오는 곳은 없다.
- application.yml:2-4 에서 spring.h2.console.enabled=false 로 설정돼 있다. datasource 설정이 없고, 클래스패스에 spring-jdbc 가 없다.

### `CVE-2021-23463|h2`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2021-23463 | GHSA-7rpj-hg47-cx62 | 8.1 | 0.0279 (백분위 86.4%) | 미등재 | 2.0.202 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): The package com.h2database:h2 from 1.4.198 and before 2.0.202 are vulnerable to XML External Entity (XXE) Injection via the org.h2.jdbc.JdbcSQLXML class object, when it receives parsed string data from org.h2.jdbc.JdbcResultSet.getSQLXML() method. If it executes the getSource() method when the param

### `CVE-2022-23221|h2`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2022-23221 | GHSA-45hx-wfhj-473x | 9.8 | 0.6477 (백분위 99.2%) | 미등재 | 2.1.210 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): H2 Console before 2.1.210 allows remote attackers to execute arbitrary code via a jdbc:h2:mem JDBC URL containing the IGNORE_UNKNOWN_SETTINGS=TRUE;FORBID_CREATION=FALSE;INIT=RUNSCRIPT substring, a different vulnerability than CVE-2021-42392.

## jackson-core 2.13.2 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-json 을 거쳐 들어온 간접 의존성이다(2.13.2). 코드에서 직접 가져오는 곳은 없다.
- 컨트롤러에 JSON 요청 본문을 받는 엔드포인트(@RequestBody)는 없다.

### `CVE-2026-89425|jackson-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-89425 | GHSA-7hhh-6rmp-j9qf | 7.5 | 0.0053 (백분위 45.0%) | 미등재 | 2.18.11 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): UTF8DataInputJsonParser._reportInvalidToken() in FasterXML jackson-core builds the offending-token text for its error message by appending Java identifier characters to a StringBuilder in a loop that has no upper bound. Unlike the three sibling parser implementations, including UTF8StreamJsonParser,

## jackson-databind 2.13.2 (2건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-json 을 거쳐 들어온 간접 의존성이다(2.13.2). 코드에서 직접 가져오는 곳은 없다.
- 컨트롤러의 세 엔드포인트는 모두 GET 이고 String 을 반환한다. @RequestBody 와 ObjectMapper 설정(default typing 등)은 없다.

### `CVE-2026-77310|jackson-databind`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-77310 | GHSA-vvgp-rfg2-7rr6 | 5.3 | 0.0031 (백분위 24.2%) | 미등재 | 2.18.9 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): jackson-databind contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. Prior to versions 2.18.9, 2.21.5, 2.22.1, 3.1.5, and 3.2.1 on their respective release lines, the java.net.InetAddress branch of FromStringDeserializer.Std._deserialize() calls InetAdd

### `CVE-2026-91776|jackson-databind`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-91776 | GHSA-wv8q-qhhj-9h54 | 7.5 | 0.0049 (백분위 41.9%) | 미등재 | 2.18.11 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): TypeDeserializerBase._findDeserializer() in FasterXML jackson-databind caches the resolved deserializer under the raw, attacker-supplied type ID. When name-based polymorphism is configured with a fallback, for example @JsonTypeInfo(use = Id.NAME, defaultImpl = ...), every distinct unrecognized type

## log4j-api 2.14.1 (1건)

**이 서비스에서 쓰이는 방식**

- build.gradle:18 에서 직접 선언(2.14.1). log4j-to-slf4j 2.17.2 가 요구하는 2.17.2 대신 2.14.1 로 해석된다.
- GreetingController.java:4-5 에서 LogManager, Logger 를 가져오고 :20 에서 요청 헤더 값을 기록한다.

### `CVE-2026-49844|log4j-api`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-49844 | GHSA-qv9r-c865-cp47 | 6.3 | 0.0060 (백분위 48.5%) | 미등재 | 2.25.5 |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/GreetingController.java:4: import org.apache.logging.log4j.LogManager;`; `src/main/java/com/example/demo/GreetingController.java:5: import org.apache.logging.log4j.Logger;`
- 설명(앞 300자): Improper encoding of non-finite floating-point values during MapMessage JSON serialization in Apache Log4j API produces output that is not valid JSON. This issue affects Apache Log4j API versions 2.13.1 through 2.25.4 and version 2.26.0.  The fix for CVE-2026-34481 did not cover all code paths: when

## log4j-core 2.14.1 (2건)

**이 서비스에서 쓰이는 방식**

- build.gradle:17 에서 직접 선언(2.14.1).
- GreetingController.java:4-5,15 에서 log4j-api 의 LogManager/Logger 를 가져오고, :19-20 에서 /hello 요청의 User-Agent 헤더 값을 log.info 의 인자로 기록한다.
- 실행 클래스패스에는 spring-boot-starter-logging 을 거쳐 들어온 log4j-to-slf4j 2.17.2 와 logback-classic 1.2.11 도 함께 있다. 저장소에 log4j2 설정 파일은 없다. LogManager 가 log4j-core 와 log4j-to-slf4j 중 어느 구현에 연결되는지는 저장소 파일만으로는 확인되지 않는다.

### `CVE-2021-44228|log4j-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | GHSA-jfh8-c2jp-5v3q | 10.0 | 1.0000 (백분위 100.0%) | 등재 | 2.15.0 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message p

### `CVE-2021-44832|log4j-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2021-44832 | GHSA-8489-44mv-ggj8 | 6.6 | 0.9791 (백분위 99.9%) | 미등재 | 2.17.1 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Apache Log4j2 versions 2.0-beta7 through 2.17.0 (excluding security fix releases 2.3.2 and 2.12.4) are vulnerable to a remote code execution (RCE) attack when a configuration uses a JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP server. This issue is f

## logback-classic 1.2.11 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-logging 을 거쳐 들어온 간접 의존성이다(1.2.11). Spring Boot 의 기본 로깅 구현이다.
- 저장소에 logback.xml, logback-spring.xml 이 없어 기본 설정으로 동작한다. 코드에서 직접 가져오는 곳은 없다.

### `CVE-2023-6378|logback-classic`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-6378 | GHSA-vmq6-5m68-f53m | 7.1 | 0.0090 (백분위 59.7%) | 미등재 | 1.2.13 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): A serialization vulnerability in logback receiver component part of  logback version 1.4.11 allows an attacker to mount a Denial-Of-Service  attack by sending poisoned data.

## logback-core 1.2.11 (2건)

**이 서비스에서 쓰이는 방식**

- logback-classic 을 거쳐 들어온 간접 의존성이다(1.2.11).
- 저장소에 logback 설정 파일이 없다. 코드에서 직접 가져오는 곳은 없다.

### `CVE-2024-12801|logback-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2024-12801 | GHSA-6v67-2wr5-gvf4 | 2.4 | 0.0023 (백분위 13.3%) | 미등재 | 1.3.15 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Server-Side Request Forgery (SSRF) in SaxEventRecorder by QOS.CH logback version 0.1 to 1.3.14 and 1.4.0 to 1.5.12  on the Java platform, allows an attacker to  forge requests by compromising logback configuration files in XML.    The attacks involves the modification of DOCTYPE declaration in  XML

### `CVE-2026-10532|logback-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-10532 | GHSA-jhq6-gfmj-v8fx | 2.9 | 0.0037 (백분위 30.9%) | 미등재 | 1.5.34 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Deserialization of untrusted data vulnerability in QOS.CH Sarl logback logback-core (HardenedObjectInputStream (logback-core) modules) allows Object Injection, albeit heavily restricted.  More precisely, an attacker able to influence serialized data sent to  SimpleSocketServer or SimpleSSLSocketServ

## snakeyaml 1.29 (2건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter 를 거쳐 들어온 간접 의존성이다(1.29). 코드에서 직접 가져오는 곳은 없다.
- Spring Boot 가 시작할 때 src/main/resources/application.yml 을 읽는 데 쓴다. 코드에는 요청으로 YAML 을 받거나 파싱하는 곳이 없다.

### `CVE-2022-38749|snakeyaml`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2022-38749 | GHSA-c4r9-r8fh-9vj2 | 6.5 | 0.0220 (백분위 82.5%) | 미등재 | 1.31 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow.

### `CVE-2022-38751|snakeyaml`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2022-38751 | GHSA-98wm-3w3q-mw94 | 6.5 | 0.0203 (백분위 81.1%) | 미등재 | 1.31 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow.

## spring-beans 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter 를 거쳐 들어온 간접 의존성이다(5.3.17). 코드에서 직접 가져오는 곳은 없다.
- /profile 의 @ModelAttribute 바인딩(GreetingController.java:32)에 프레임워크의 데이터 바인딩이 쓰인다. bootJar 로 패키징하고(WAR 아님), build.gradle:11 은 sourceCompatibility 11, 이 저장소의 빌드와 스캔은 JDK 17 로 했다.

### `CVE-2022-22965|spring-beans`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2022-22965 | GHSA-36p3-wjmg-h94x | 9.8 | 0.9964 (백분위 100.0%) | 등재 | 5.3.18 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is

## spring-boot 2.6.5 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 을 거쳐 들어온 간접 의존성이다(2.6.5).
- DemoApplication.java:3,9 에서 SpringApplication.run 으로 구동한다. actuator 는 의존성에 없다.

### `CVE-2026-40973|spring-boot`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-40973 | GHSA-wwpq-f5c3-7hvx | 7.0 | 0.0014 (백분위 3.0%) | 미등재 | - |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/DemoApplication.java:3: import org.springframework.boot.SpringApplication;`
- 설명(앞 300자): A local attacker on the same host as the application may be able to take control of the directory used by `ApplicationTemp`. When `server.servlet.session.persistent` is set to `true` and the attack persists across application restarts, this may allow the attacker to read session information and hija

## spring-boot-autoconfigure 2.6.5 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter 를 거쳐 들어온 간접 의존성이다(2.6.5).
- DemoApplication.java:4,6 의 @SpringBootApplication 으로 자동 설정이 켜진다.

### `CVE-2023-20883|spring-boot-autoconfigure`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-20883 | GHSA-xf96-w227-r7c4 | 7.5 | 0.0091 (백분위 60.0%) | 미등재 | 2.6.15 |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/DemoApplication.java:4: import org.springframework.boot.autoconfigure.SpringBootApplication;`
- 설명(앞 300자): In Spring Boot versions 3.0.0 - 3.0.6, 2.7.0 - 2.7.11, 2.6.0 - 2.6.14, 2.5.0 - 2.5.14 and older unsupported versions, there is potential for a denial-of-service (DoS) attack if Spring MVC is used together with a reverse proxy cache.

## spring-context 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter 를 거쳐 들어온 간접 의존성이다(5.3.17). 코드에서 직접 가져오는 곳은 없다.
- 애플리케이션 컨텍스트 구동에 쓰인다(DemoApplication.java:9).

### `CVE-2024-38820|spring-context`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2024-38820 | GHSA-4gc7-5j7h-4qph | 5.3 | 0.0062 (백분위 49.6%) | 미등재 | - |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): The fix for CVE-2022-22968 made disallowedFields patterns in DataBinder case insensitive. However, String.toLowerCase() has some Locale dependent exceptions that could potentially result in fields not protected as expected.

## spring-core 5.3.17 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot 를 거쳐 들어온 간접 의존성이다(5.3.17). 코드에서 직접 가져오는 곳은 없다.
- 모든 Spring 모듈의 기반이다.

### `CVE-2026-41848|spring-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-41848 | GHSA-659m-px2c-25wj | 3.7 | 0.0034 (백분위 26.9%) | 미등재 | - |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Applications may be vulnerable to a Regular Expression Denial of Service (ReDoS) attack if an attacker is able to provide a pattern which is then directly or indirectly supplied to one of the following methods in AntPathMatcher: match(String pattern, String path), matchStart(String pattern, String p

## spring-expression 5.3.17 (2건)

**이 서비스에서 쓰이는 방식**

- spring-context 와 spring-webmvc 를 거쳐 들어온 간접 의존성이다(5.3.17).
- 코드에서 SpEL(ExpressionParser, @Value 의 #{...})을 직접 쓰는 곳은 없다.

### `CVE-2023-20861|spring-expression`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-20861 | GHSA-564r-hj7v-mcr5 | 6.5 | 0.0097 (백분위 61.9%) | 미등재 | 5.3.26 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): In Spring Framework versions 6.0.0 - 6.0.6, 5.3.0 - 5.3.25, 5.2.0.RELEASE - 5.2.22.RELEASE, and older unsupported versions, it is possible for a user to provide a specially crafted SpEL expression that may cause a denial-of-service (DoS) condition.

### `CVE-2026-41849|spring-expression`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-41849 | GHSA-775g-4xr8-78h8 | 7.5 | 0.0026 (백분위 18.2%) | 미등재 | - |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): An integer overflow vulnerability exists in the evaluation logic of the Spring Expression Language (SpEL). An attacker can exploit this by supplying a specially crafted SpEL expression that triggers excessive resource consumption, resulting in a Denial of Service (DoS).  Affected versions: Spring Fr

## spring-web 5.3.17 (2건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 을 거쳐 들어온 간접 의존성이다(5.3.17).
- GreetingController.java:6-10 에서 org.springframework.web.bind.annotation 의 어노테이션(GetMapping, RequestParam, RequestHeader, ModelAttribute, RestController)을 가져온다.

### `CVE-2024-22243|spring-web`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2024-22243 | GHSA-ccgv-vj62-xf9h | 8.1 | 0.0397 (백분위 90.5%) | 미등재 | 5.3.32 |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/GreetingController.java:6: import org.springframework.web.bind.annotation.GetMapping;`; `src/main/java/com/example/demo/GreetingController.java:7: import org.springframework.web.bind.annotation.ModelAttribute;`; `src/main/java/com/example/demo/GreetingController.java:8: import org.springframework.web.bind.annotation.RequestHeader;`; `src/main/java/com/example/demo/GreetingController.java:9: import org.springframework.web.bind.annotation.RequestParam;`; `src/main/java/com/example/demo/GreetingController.java:10: import org.springframework.web.bind.annotation.RestController;`
- 설명(앞 300자): Applications that use UriComponentsBuilder to parse an externally provided URL (e.g. through a query parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a  open redirect https://cwe.mitre.org/data/definitions/601.html  attack or to a SSRF attack if the URL is

### `CVE-2024-22262|spring-web`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2024-22262 | GHSA-2wrp-6fg6-hmc5 | 8.1 | 0.0119 (백분위 68.0%) | 미등재 | 5.3.34 |

- 직접 사용 위치(import 기준): `src/main/java/com/example/demo/GreetingController.java:6: import org.springframework.web.bind.annotation.GetMapping;`; `src/main/java/com/example/demo/GreetingController.java:7: import org.springframework.web.bind.annotation.ModelAttribute;`; `src/main/java/com/example/demo/GreetingController.java:8: import org.springframework.web.bind.annotation.RequestHeader;`; `src/main/java/com/example/demo/GreetingController.java:9: import org.springframework.web.bind.annotation.RequestParam;`; `src/main/java/com/example/demo/GreetingController.java:10: import org.springframework.web.bind.annotation.RestController;`
- 설명(앞 300자): Applications that use UriComponentsBuilder to parse an externally provided URL (e.g. through a query parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a  open redirect https://cwe.mitre.org/data/definitions/601.html  attack or to a SSRF attack if the URL is

## spring-webmvc 5.3.17 (2건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 을 거쳐 들어온 간접 의존성이다(5.3.17). GreetingController 의 @RestController 가 /hello, /template, /profile(모두 GET)을 처리한다.
- /profile 은 요청 값을 @ModelAttribute 로 Profile 객체에 바인딩한다(GreetingController.java:31-33). 정적 리소스 설정과 뷰 템플릿은 없다.

### `CVE-2024-38819|spring-webmvc`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2024-38819 | GHSA-g5vr-rgqm-vf78 | 7.5 | 0.5646 (백분위 99.1%) | 미등재 | - |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on the file system that is also accessible to the process in which the Spring application is

### `CVE-2026-41853|spring-webmvc`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2026-41853 | GHSA-cjpg-rgq5-fr37 | 5.3 | 0.0019 (백분위 8.2%) | 미등재 | - |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Spring MVC and WebFlux applications are vulnerable to Multipart request smuggling attacks.  Affected versions: Spring Framework 7.0.0 through 7.0.7; 6.2.0 through 6.2.18; 6.1.0 through 6.1.27; 5.3.0 through 5.3.48.

## tomcat-embed-core 9.0.60 (2건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-web 에서 spring-boot-starter-tomcat 을 거쳐 들어온 내장 서버다(9.0.60). bootJar(실행형 jar)로 패키징한다.
- 모든 HTTP 요청을 받는다(application.yml:6, server.port 8080). 그 밖의 Tomcat 설정(커넥터, AJP, 세션 저장 등)은 저장소에 없다.

### `CVE-2025-53506|tomcat-embed-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2025-53506 | GHSA-25xr-qj8w-c4vf | 7.5 | 0.0213 (백분위 81.9%) | 미등재 | 9.0.107 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Uncontrolled Resource Consumption vulnerability in Apache Tomcat if an HTTP/2 client did not acknowledge the initial settings frame that reduces the maximum permitted concurrent streams.  This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.8, from 10.1.0-M1 through 10.1.42, from 9.0.0.M1 t

### `CVE-2025-55668|tomcat-embed-core`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2025-55668 | GHSA-23hv-mwm6-g8jf | 6.5 | 0.0086 (백분위 58.5%) | 미등재 | 9.0.106 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Session Fixation vulnerability in Apache Tomcat via rewrite valve.  This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.7, from 10.1.0-M1 through 10.1.41, from 9.0.0.M1 through 9.0.105. Older, EOL versions may also be affected.  Users are recommended to upgrade to version 11.0.8, 10.1.42 o

## tomcat-embed-websocket 9.0.60 (1건)

**이 서비스에서 쓰이는 방식**

- spring-boot-starter-tomcat 을 거쳐 들어온 간접 의존성이다(9.0.60).
- 코드에 WebSocket 엔드포인트(@ServerEndpoint, WebSocketConfigurer 등)가 없다.

### `CVE-2024-23672|tomcat-embed-websocket`

| 취약점 | 다른 식별자 | CVSS | EPSS | KEV | 수정 버전 |
| --- | --- | --- | --- | --- | --- |
| CVE-2024-23672 | GHSA-v682-8vv8-vpwr | 6.3 | 0.0231 (백분위 83.4%) | 미등재 | 9.0.86 |

- 직접 사용 위치(import 기준): 없음
- 설명(앞 300자): Denial of Service via incomplete cleanup vulnerability in Apache Tomcat. It was possible for WebSocket clients to keep WebSocket connections open leading to increased resource consumption.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-
