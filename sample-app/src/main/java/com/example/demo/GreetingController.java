package com.example.demo;

import org.apache.commons.text.StringSubstitutor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    private static final Logger log = LogManager.getLogger(GreetingController.class);

    // 외부 요청 헤더를 그대로 로그에 남긴다.
    @GetMapping("/hello")
    public String hello(@RequestHeader(value = "User-Agent", defaultValue = "") String userAgent) {
        log.info("hello called by {}", userAgent);
        return "hello";
    }

    // 사용자 입력을 문자열 치환기에 그대로 넣는다.
    @GetMapping("/template")
    public String template(@RequestParam String text) {
        return StringSubstitutor.createInterpolator().replace(text);
    }

    // 요청 값을 일반 객체에 바인딩한다.
    @GetMapping("/profile")
    public String profile(@ModelAttribute Profile profile) {
        return profile.getName();
    }
}
