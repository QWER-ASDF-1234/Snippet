package com.develop.snippet.global.security.oauth;

import com.develop.snippet.domain.user.domain.AuthProvider;

import java.util.Map;

public interface OAuthUserInfo {

    String getProviderId();      // OAuth provider의 고유 ID (sub)
    String getEmail();
    String getName();
    Boolean getEmailVerified();
    AuthProvider getProvider();

    static OAuthUserInfo of(AuthProvider provider, Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> new GoogleUserInfo(attributes);
            default -> throw new IllegalArgumentException("지원하지 않는 OAuth Provider: " + provider);
        };
    }
}