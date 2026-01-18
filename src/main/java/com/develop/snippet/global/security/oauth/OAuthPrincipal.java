package com.develop.snippet.global.security.oauth;

import com.develop.snippet.domain.user.domain.AuthProvider;
import com.develop.snippet.domain.user.domain.UserRole;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@Getter
public class OAuthPrincipal implements OidcUser {  // OAuth2User -> OidcUser로 변경

    private final Long userId;
    private final String email;
    private final String name;
    private final AuthProvider provider;
    private final UserRole role;
    private final Map<String, Object> attributes;
    private final OidcIdToken idToken;          // 추가
    private final OidcUserInfo userInfo;        // 추가

    public OAuthPrincipal(
            Long userId,
            String email,
            String name,
            AuthProvider provider,
            UserRole role,
            Map<String, Object> attributes,
            OidcIdToken idToken,
            OidcUserInfo userInfo
    ) {
        this.userId = userId;
        this.email = email;
        this.name = name;
        this.provider = provider;
        this.role = role;
        this.attributes = attributes;
        this.idToken = idToken;
        this.userInfo = userInfo;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_" + role.name())
        );
    }

    @Override
    public String getName() {
        return name;
    }

    // OidcUser 인터페이스 구현
    @Override
    public Map<String, Object> getClaims() {
        return idToken != null ? idToken.getClaims() : Collections.emptyMap();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return userInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }
}