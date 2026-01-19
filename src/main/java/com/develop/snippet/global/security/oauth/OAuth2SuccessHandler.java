package com.develop.snippet.global.security.oauth;

import com.develop.snippet.domain.auth.domain.RefreshToken;
import com.develop.snippet.domain.auth.repository.RefreshTokenRepository;
import com.develop.snippet.global.security.jwt.JwtProperties;
import com.develop.snippet.global.security.jwt.JwtProvider;
import com.develop.snippet.global.util.CookieUtil;
import com.develop.snippet.global.util.HashUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDateTime;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.security.oauth2.success-redirect-url}")
    private String successRedirectUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        OAuthPrincipal principal = (OAuthPrincipal) authentication.getPrincipal();

        log.info("OAuth2 Login Success - UserId: {}, Email: {}, Provider: {}",
                principal.getUserId(), principal.getEmail(), principal.getProvider());

        // 1. Access Token 생성
        String accessToken = jwtProvider.createAccessToken(
                principal.getUserId(),
                principal.getEmail(),
                principal.getRole()
        );

        // 2. Refresh Token 생성
        String refreshToken = jwtProvider.createRefreshToken(principal.getUserId());

        // 3. Refresh Token DB 저장
        saveRefreshToken(
                principal.getUserId(),
                refreshToken,
                request.getHeader("User-Agent"),
                getClientIp(request)
        );

        // 4. Refresh Token을 HttpOnly 쿠키로 설정
        CookieUtil.addRefreshTokenCookie(response, refreshToken, jwtProperties);

        // 5. Access Token을 쿼리 파라미터로 전달
        String targetUrl = UriComponentsBuilder.fromUriString(successRedirectUrl)
                .queryParam("accessToken", accessToken)
                .queryParam("userId", principal.getUserId())
                .queryParam("email", principal.getEmail())
                .queryParam("provider", principal.getProvider())
                .build()
                .toUriString();

        log.info("Redirecting to: {}", targetUrl);

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private void saveRefreshToken(Long userId, String refreshToken, String userAgent, String ipAddress) {
        String tokenHash = HashUtil.sha256(refreshToken);
        LocalDateTime expiresAt = LocalDateTime.now()
                .plusDays(jwtProperties.getRefreshTokenDays());

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .userId(userId)
                .refreshTokenHash(tokenHash)
                .expiresAt(expiresAt)
                .userAgent(userAgent)
                .ipAddress(ipAddress)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);
        log.debug("Refresh Token saved for userId: {}", userId);
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");

        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip;
    }
}