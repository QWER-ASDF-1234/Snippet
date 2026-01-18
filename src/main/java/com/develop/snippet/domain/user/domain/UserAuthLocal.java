package com.develop.snippet.domain.user.domain;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_auth_local")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EntityListeners(AuditingEntityListener.class)
public class UserAuthLocal {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "password_updated_at")
    private LocalDateTime passwordUpdatedAt;

    @Column(name = "failed_login_count", nullable = false)
    private Integer failedLoginCount = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Builder
    public UserAuthLocal(Long userId, String passwordHash) {
        this.userId = userId;
        this.passwordHash = passwordHash;
        this.passwordUpdatedAt = LocalDateTime.now();
        this.failedLoginCount = 0;
    }

    // 비즈니스 메서드
    public void updatePassword(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
        this.passwordUpdatedAt = LocalDateTime.now();
    }

    public void recordFailedLogin() {
        this.failedLoginCount++;

        // 5회 실패 시 30분 잠금
        if (this.failedLoginCount >= 5) {
            this.lockedUntil = LocalDateTime.now().plusMinutes(30);
        }
    }

    public void resetFailedLoginCount() {
        this.failedLoginCount = 0;
        this.lockedUntil = null;
    }

    public void recordSuccessfulLogin() {
        this.lastLoginAt = LocalDateTime.now();
        resetFailedLoginCount();
    }

    public boolean isLocked() {
        if (lockedUntil == null) {
            return false;
        }

        if (LocalDateTime.now().isAfter(lockedUntil)) {
            this.lockedUntil = null;
            this.failedLoginCount = 0;
            return false;
        }

        return true;
    }
}