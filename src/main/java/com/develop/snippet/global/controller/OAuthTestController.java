package com.develop.snippet.global.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/test/oauth")
public class OAuthTestController {

    @GetMapping("/success")
    public Map<String, Object> oauthSuccess(
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String provider,
            HttpServletRequest request
    ) {
        log.info("=== OAuth Login Success ===");
        log.info("UserId: {}", userId);
        log.info("Email: {}", email);
        log.info("Provider: {}", provider);
        log.info("Request URL: {}", request.getRequestURL());

        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("userId", userId);
        response.put("email", email);
        response.put("provider", provider);
        response.put("message", "OAuth 로그인 성공!");

        return response;
    }

    @GetMapping("/failure")
    public Map<String, Object> oauthFailure(
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String message,
            HttpServletRequest request
    ) {
        log.error("=== OAuth Login Failed ===");
        log.error("Error: {}", error);
        log.error("Message: {}", message);
        log.error("Request URL: {}", request.getRequestURL());

        Map<String, Object> response = new HashMap<>();
        response.put("status", "failure");
        response.put("error", error);
        response.put("message", message != null ? message : "OAuth 로그인 실패");

        return response;
    }
}