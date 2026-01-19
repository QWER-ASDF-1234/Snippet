package com.develop.snippet.global.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ApiErrorCode {

  // 공통
  INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다."),
  INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST, "잘못된 입력값입니다."),

  // 인증/인가
  UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "인증이 필요합니다."),
  FORBIDDEN(HttpStatus.FORBIDDEN, "접근 권한이 없습니다."),
  INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 Refresh Token입니다."),
  INVALID_TOKEN_TYPE(HttpStatus.BAD_REQUEST, "잘못된 토큰 타입입니다."),
  REFRESH_TOKEN_NOT_FOUND(HttpStatus.UNAUTHORIZED, "Refresh Token을 찾을 수 없습니다."),
  REVOKED_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "무효화된 Refresh Token입니다."),
  EXPIRED_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 Refresh Token입니다."),

  // 사용자
  USER_NOT_FOUND(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다."),
  USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 존재하는 사용자입니다.");

  private final HttpStatus status;
  private final String message;
}