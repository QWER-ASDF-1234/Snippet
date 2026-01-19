package com.develop.snippet.domain.auth.controller;

import com.develop.snippet.domain.auth.dto.request.RefreshRequest;
import com.develop.snippet.domain.auth.dto.response.TokenResponse;
import com.develop.snippet.domain.auth.service.AuthService;
import com.develop.snippet.global.response.ApiResponse;
import com.develop.snippet.global.security.principal.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;

  /**
   * Access Token 재발급
   */
  @PostMapping("/refresh")
  public ResponseEntity<ApiResponse<TokenResponse>> refresh(
          @Valid @RequestBody RefreshRequest request,
          HttpServletRequest httpRequest
  ) {
    TokenResponse tokenResponse = authService.refreshAccessToken(request, httpRequest);
    return ResponseEntity.ok(ApiResponse.success(tokenResponse));
  }

  /**
   * 로그아웃 (현재 디바이스만)
   */
  @PostMapping("/logout")
  public ResponseEntity<ApiResponse<Void>> logout(
          HttpServletRequest request,
          HttpServletResponse response
  ) {
    authService.logout(request, response);
    return ResponseEntity.ok(ApiResponse.success(null, "로그아웃 되었습니다."));
  }

  /**
   * 모든 디바이스 로그아웃
   */
  @PostMapping("/logout-all")
  public ResponseEntity<ApiResponse<Void>> logoutAll(
          @AuthenticationPrincipal UserPrincipal userPrincipal,
          HttpServletResponse response
  ) {
    authService.logoutAll(userPrincipal.getUserId(), response);
    return ResponseEntity.ok(ApiResponse.success(null, "모든 디바이스에서 로그아웃 되었습니다."));
  }
}