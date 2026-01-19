package com.develop.snippet.global.util;

import com.develop.snippet.global.security.jwt.JwtProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;

public class CookieUtil {

  /**
   * 쿠키에서 Refresh Token 추출
   */
  public static String getRefreshToken(HttpServletRequest request, String cookieName) {
    if (request.getCookies() == null) {
      return null;
    }

    return Arrays.stream(request.getCookies())
            .filter(cookie -> cookieName.equals(cookie.getName()))
            .findFirst()
            .map(Cookie::getValue)
            .orElse(null);
  }

  /**
   * Refresh Token 쿠키 생성
   */
  public static void addRefreshTokenCookie(
          HttpServletResponse response,
          String refreshToken,
          JwtProperties jwtProperties
  ) {
    Cookie cookie = new Cookie(jwtProperties.getRefreshCookieName(), refreshToken);
    cookie.setHttpOnly(true);
    cookie.setSecure(jwtProperties.getRefreshCookieSecure());
    cookie.setPath(jwtProperties.getRefreshCookiePath());
    cookie.setMaxAge(jwtProperties.getRefreshTokenDays() * 24 * 60 * 60);

    String sameSite = jwtProperties.getRefreshCookieSameSite();
    if ("None".equalsIgnoreCase(sameSite)) {
      response.setHeader("Set-Cookie",
              String.format("%s=%s; Path=%s; Max-Age=%d; HttpOnly; Secure; SameSite=None",
                      cookie.getName(),
                      cookie.getValue(),
                      cookie.getPath(),
                      cookie.getMaxAge()
              )
      );
    } else {
      response.addCookie(cookie);
    }
  }

  /**
   * Refresh Token 쿠키 삭제
   */
  public static void deleteRefreshTokenCookie(
          HttpServletResponse response,
          JwtProperties jwtProperties
  ) {
    Cookie cookie = new Cookie(jwtProperties.getRefreshCookieName(), null);
    cookie.setHttpOnly(true);
    cookie.setSecure(jwtProperties.getRefreshCookieSecure());
    cookie.setPath(jwtProperties.getRefreshCookiePath());
    cookie.setMaxAge(0);  // 즉시 삭제

    response.addCookie(cookie);
  }
}