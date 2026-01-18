package com.develop.snippet.global.security.jwt;

import com.develop.snippet.domain.user.domain.UserRole;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        String secret = jwtProperties.getSecret();

        // 디버그: 실제 로드된 값 확인
        log.info("=== JWT Secret Debug ===");
        log.info("Secret value: {}", secret);
        log.info("Secret length: {} characters", secret != null ? secret.length() : 0);

        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("JWT Secret is null or empty");
        }

        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        log.info("Secret bytes: {} bytes", keyBytes.length);

        if (keyBytes.length < 64) {
            throw new IllegalArgumentException(
                    String.format("JWT Secret key length must be at least 64 bytes for HS512. Current: %d bytes",
                            keyBytes.length)
            );
        }

        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        log.info("JWT Secret Key initialized successfully");
    }

    /**
     * Access Token 생성
     */
    public String createAccessToken(Long userId, String email, UserRole role) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiryDate = now.plusMinutes(jwtProperties.getAccessTokenMinutes());

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("role", role.name())
                .claim("type", "ACCESS")
                .issuer(jwtProperties.getIssuer())
                .issuedAt(toDate(now))
                .expiration(toDate(expiryDate))
                .signWith(secretKey, Jwts.SIG.HS512)  // ← 변경
                .compact();
    }

    /**
     * Refresh Token 생성 (userId만 포함)
     */
    public String createRefreshToken(Long userId) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiryDate = now.plusDays(jwtProperties.getRefreshTokenDays());

        return Jwts.builder()
                .subject(userId.toString())
                .claim("type", "REFRESH")
                .issuer(jwtProperties.getIssuer())
                .issuedAt(toDate(now))
                .expiration(toDate(expiryDate))
                .signWith(secretKey, Jwts.SIG.HS512)  // ← 변경
                .compact();
    }

    /**
     * JWT에서 Claims 추출
     */
    public Claims parseClaims(String token) {
        try {
            return Jwts.parser()  // ← 변경: parserBuilder() -> parser()
                    .verifyWith(secretKey)  // ← 변경: setSigningKey() -> verifyWith()
                    .build()
                    .parseSignedClaims(token)  // ← 변경: parseClaimsJws() -> parseSignedClaims()
                    .getPayload();  // ← 변경: getBody() -> getPayload()
        } catch (ExpiredJwtException e) {
            // 만료된 토큰도 Claims는 추출 가능
            return e.getClaims();
        }
    }

    /**
     * JWT에서 userId 추출
     */
    public Long getUserId(String token) {
        Claims claims = parseClaims(token);
        return Long.parseLong(claims.getSubject());
    }

    /**
     * JWT에서 email 추출
     */
    public String getEmail(String token) {
        Claims claims = parseClaims(token);
        return claims.get("email", String.class);
    }

    /**
     * JWT에서 role 추출
     */
    public UserRole getRole(String token) {
        Claims claims = parseClaims(token);
        String role = claims.get("role", String.class);
        return UserRole.valueOf(role);
    }

    /**
     * JWT 유효성 검증
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()  // ← 변경
                    .verifyWith(secretKey)  // ← 변경
                    .build()
                    .parseSignedClaims(token);  // ← 변경
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Access Token인지 확인
     */
    public boolean isAccessToken(String token) {
        try {
            Claims claims = parseClaims(token);
            String type = claims.get("type", String.class);
            return "ACCESS".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Refresh Token인지 확인
     */
    public boolean isRefreshToken(String token) {
        try {
            Claims claims = parseClaims(token);
            String type = claims.get("type", String.class);
            return "REFRESH".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 토큰 만료 시간 반환
     */
    public LocalDateTime getExpirationDate(String token) {
        Claims claims = parseClaims(token);
        Date expiration = claims.getExpiration();
        return expiration.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }

    /**
     * LocalDateTime -> Date 변환
     */
    private Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}