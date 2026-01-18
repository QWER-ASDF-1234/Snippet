package com.develop.snippet.global.security.oauth;

import com.develop.snippet.domain.user.domain.AuthProvider;
import com.develop.snippet.domain.user.domain.OAuthAccount;
import com.develop.snippet.domain.user.domain.User;
import com.develop.snippet.domain.user.domain.UserRole;
import com.develop.snippet.domain.user.repository.OAuthAccountRepository;
import com.develop.snippet.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends OidcUserService {  // 변경

    private final UserRepository userRepository;
    private final OAuthAccountRepository oAuthAccountRepository;

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {  // 변경
        // 1. OAuth2 제공자로부터 사용자 정보 가져오기
        OidcUser oidcUser = super.loadUser(userRequest);

        // 2. Provider 확인
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());

        // 3. Provider별 사용자 정보 파싱
        OAuthUserInfo userInfo = OAuthUserInfo.of(provider, oidcUser.getAttributes());

        log.info("OAuth2 Login - Provider: {}, Email: {}, ProviderId: {}",
                provider, userInfo.getEmail(), userInfo.getProviderId());

        // 4. OAuth 계정 조회 또는 생성
        OAuthAccount oAuthAccount = oAuthAccountRepository
                .findByProviderAndProviderSubject(provider, userInfo.getProviderId())
                .orElseGet(() -> createNewOAuthAccount(userInfo));

        // 5. 마지막 로그인 시간 업데이트
        oAuthAccount.updateLastLogin();

        // 6. User 조회
        User user = userRepository.findById(oAuthAccount.getUserId())
                .orElseThrow(() -> new OAuth2AuthenticationException("사용자를 찾을 수 없습니다."));

        // 7. OAuthPrincipal 반환
        return new OAuthPrincipal(
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                provider,
                user.getRole(),
                oidcUser.getAttributes(),
                oidcUser.getIdToken(),        // 추가
                oidcUser.getUserInfo()        // 추가
        );
    }

    private OAuthAccount createNewOAuthAccount(OAuthUserInfo userInfo) {
        // 1. User 생성 또는 조회
        User user = userRepository.findByEmail(userInfo.getEmail())
                .orElseGet(() -> createNewUser(userInfo));

        // 2. OAuthAccount 생성
        OAuthAccount oAuthAccount = OAuthAccount.builder()
                .userId(user.getId())
                .provider(userInfo.getProvider())
                .providerSubject(userInfo.getProviderId())
                .email(userInfo.getEmail())
                .emailVerified(userInfo.getEmailVerified())
                .build();

        return oAuthAccountRepository.save(oAuthAccount);
    }

    private User createNewUser(OAuthUserInfo userInfo) {
        User user = User.builder()
                .email(userInfo.getEmail())
                .displayName(userInfo.getName())
                .role(UserRole.USER)
                .build();

        return userRepository.save(user);
    }
}