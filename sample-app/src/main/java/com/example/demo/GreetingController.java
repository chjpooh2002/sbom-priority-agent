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

    @GetMapping("/hello")
    public String hello(@RequestHeader(value = "User-Agent", defaultValue = "") String userAgent) {
        log.info("hello called by {}", userAgent);
        return "hello";
    }

    @GetMapping("/template")
    public String template(@RequestParam String text) {
        return StringSubstitutor.createInterpolator().replace(text);
    }

    @GetMapping("/profile")
    public String profile(@ModelAttribute Profile profile) {
        return profile.getName();
    }
}
