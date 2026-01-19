package com.develop.snippet.domain.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TokenResponse {

  private String accessToken;
  private String tokenType;
  private Long expiresIn;  // 초 단위

  public static TokenResponse of(String accessToken, Long expiresIn) {
    return new TokenResponse(accessToken, "Bearer", expiresIn);
  }
}