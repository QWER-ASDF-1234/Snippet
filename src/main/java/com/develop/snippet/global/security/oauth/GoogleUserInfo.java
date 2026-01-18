package com.develop.snippet.global.security.oauth;

import com.develop.snippet.domain.user.domain.AuthProvider;

import java.util.Map;

public class GoogleUserInfo implements OAuthUserInfo {

    private final Map<String, Object> attributes;

    public GoogleUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public Boolean getEmailVerified() {
        Object verified = attributes.get("email_verified");
        if (verified instanceof Boolean) {
            return (Boolean) verified;
        }
        return false;
    }

    @Override
    public AuthProvider getProvider() {
        return AuthProvider.GOOGLE;
    }
}