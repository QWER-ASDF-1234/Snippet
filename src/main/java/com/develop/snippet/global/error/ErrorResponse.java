package com.develop.snippet.global.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class ErrorResponse {

  private int status;
  private String error;
  private String message;
  private LocalDateTime timestamp;

  public static ErrorResponse of(HttpStatus status, String message) {
    return new ErrorResponse(
            status.value(),
            status.getReasonPhrase(),
            message,
            LocalDateTime.now()
    );
  }

  public static ErrorResponse of(ApiErrorCode errorCode) {
    return new ErrorResponse(
            errorCode.getStatus().value(),
            errorCode.getStatus().getReasonPhrase(),
            errorCode.getMessage(),
            LocalDateTime.now()
    );
  }
}