package com.develop.snippet.domain.user.repository;

import com.develop.snippet.domain.user.domain.AuthProvider;
import com.develop.snippet.domain.user.domain.OAuthAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OAuthAccountRepository extends JpaRepository<OAuthAccount, Long> {

    Optional<OAuthAccount> findByProviderAndProviderSubject(
            AuthProvider provider,
            String providerSubject
    );

    List<OAuthAccount> findByUserId(Long userId);

    Optional<OAuthAccount> findByUserIdAndProvider(Long userId, AuthProvider provider);

    boolean existsByProviderAndProviderSubject(
            AuthProvider provider,
            String providerSubject
    );
}