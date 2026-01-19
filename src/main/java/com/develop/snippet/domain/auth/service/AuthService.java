package com.develop.snippet.domain.auth.service;

import com.develop.snippet.domain.auth.domain.RefreshToken;
import com.develop.snippet.domain.auth.dto.request.RefreshRequest;
import com.develop.snippet.domain.auth.dto.response.TokenResponse;
import com.develop.snippet.domain.auth.repository.RefreshTokenRepository;
import com.develop.snippet.domain.user.domain.User;
import com.develop.snippet.domain.user.repository.UserRepository;
import com.develop.snippet.global.error.ApiErrorCode;
import com.develop.snippet.global.error.ApiException;
import com.develop.snippet.global.security.jwt.JwtProperties;
import com.develop.snippet.global.security.jwt.JwtProvider;
import com.develop.snippet.global.util.CookieUtil;
import com.develop.snippet.global.util.HashUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

  private final JwtProvider jwtProvider;
  private final JwtProperties jwtProperties;
  private final RefreshTokenRepository refreshTokenRepository;
  private final UserRepository userRepository;

  /**
   * Refresh Token으로 Access Token 재발급
   */
  @Transactional
  public TokenResponse refreshAccessToken(RefreshRequest request, HttpServletRequest httpRequest) {
    // 1. Refresh Token 가져오기 (Request Body 우선, 없으면 Cookie)
    String refreshToken = request.getRefreshToken();
    if (refreshToken == null || refreshToken.isEmpty()) {
      refreshToken = CookieUtil.getRefreshToken(httpRequest, jwtProperties.getRefreshCookieName());
    }

    if (refreshToken == null || refreshToken.isEmpty()) {
      throw new ApiException(ApiErrorCode.REFRESH_TOKEN_NOT_FOUND);
    }

    // 2. Refresh Token 유효성 검증
    if (!jwtProvider.validateToken(refreshToken)) {
      throw new ApiException(ApiErrorCode.INVALID_REFRESH_TOKEN);
    }

    // 3. Refresh Token 타입 확인
    if (!jwtProvider.isRefreshToken(refreshToken)) {
      throw new ApiException(ApiErrorCode.INVALID_TOKEN_TYPE);
    }

    // 4. Refresh Token 해시 계산 및 DB 조회
    String tokenHash = HashUtil.sha256(refreshToken);
    RefreshToken storedToken = refreshTokenRepository
            .findByRefreshTokenHash(tokenHash)
            .orElseThrow(() -> new ApiException(ApiErrorCode.REFRESH_TOKEN_NOT_FOUND));

    // 5. Revoked/만료 확인
    if (storedToken.getRevoked()) {
      throw new ApiException(ApiErrorCode.REVOKED_REFRESH_TOKEN);
    }
    if (storedToken.isExpired()) {
      throw new ApiException(ApiErrorCode.EXPIRED_REFRESH_TOKEN);
    }

    // 6. User 조회
    User user = userRepository.findById(storedToken.getUserId())
            .orElseThrow(() -> new ApiException(ApiErrorCode.USER_NOT_FOUND));

    // 7. 새로운 Access Token 생성
    String newAccessToken = jwtProvider.createAccessToken(
            user.getId(),
            user.getEmail(),
            user.getRole()
    );

    log.info("Access Token refreshed for userId: {}", user.getId());

    // 8. 응답 생성
    Long expiresIn = jwtProperties.getAccessTokenMinutes() * 60L;
    return TokenResponse.of(newAccessToken, expiresIn);
  }

  /**
   * 로그아웃 (현재 디바이스만)
   */
  @Transactional
  public void logout(HttpServletRequest request, HttpServletResponse response) {
    // 1. 쿠키에서 Refresh Token 가져오기
    String refreshToken = CookieUtil.getRefreshToken(request, jwtProperties.getRefreshCookieName());

    // 2. Refresh Token이 없으면 무시
    if (refreshToken == null || refreshToken.isEmpty()) {
      log.info("Logout called with no refresh token");
      CookieUtil.deleteRefreshTokenCookie(response, jwtProperties);
      return;
    }

    // 3. Refresh Token 해시 계산 및 무효화
    String tokenHash = HashUtil.sha256(refreshToken);
    refreshTokenRepository.findByRefreshTokenHash(tokenHash)
            .ifPresent(token -> {
              token.revoke();
              refreshTokenRepository.save(token);
              log.info("Refresh Token revoked for userId: {}", token.getUserId());
            });

    // 4. 쿠키 삭제
    CookieUtil.deleteRefreshTokenCookie(response, jwtProperties);
  }

  /**
   * 모든 디바이스 로그아웃
   */
  @Transactional
  public void logoutAll(Long userId, HttpServletResponse response) {
    // 1. 사용자의 모든 Refresh Token 무효화
    refreshTokenRepository.revokeAllByUserId(userId);
    log.info("All refresh tokens revoked for userId: {}", userId);

    // 2. 쿠키 삭제
    CookieUtil.deleteRefreshTokenCookie(response, jwtProperties);
  }
}