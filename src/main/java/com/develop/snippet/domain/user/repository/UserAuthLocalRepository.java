package com.develop.snippet.domain.user.repository;

import com.develop.snippet.domain.user.domain.UserAuthLocal;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthLocalRepository extends JpaRepository<UserAuthLocal, Long> {

    Optional<UserAuthLocal> findByUserId(Long userId);

    boolean existsByUserId(Long userId);
}