package com.develop.snippet.global.security.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.security.jwt")
public class JwtProperties {

    private String secret;
    private String issuer;
    private Integer accessTokenMinutes;
    private Integer refreshTokenDays;
    private String refreshCookieName;
    private String refreshCookiePath;
    private Boolean refreshCookieSecure;
    private String refreshCookieSameSite;
}