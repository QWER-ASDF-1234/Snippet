package com.develop.snippet.domain.user.controller;

import com.develop.snippet.global.security.principal.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    /**
     * 현재 로그인한 사용자 정보 조회
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(
            @AuthenticationPrincipal UserPrincipal userPrincipal
    ) {
        Map<String, Object> response = new HashMap<>();
        response.put("userId", userPrincipal.getUserId());
        response.put("email", userPrincipal.getEmail());
        response.put("role", userPrincipal.getRole());

        return ResponseEntity.ok(response);
    }
}