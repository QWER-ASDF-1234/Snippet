package com.develop.snippet.global.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  /**
   * ApiException 처리
   */
  @ExceptionHandler(ApiException.class)
  public ResponseEntity<ErrorResponse> handleApiException(ApiException e) {
    log.error("ApiException: {}", e.getMessage(), e);

    ErrorResponse response = ErrorResponse.of(e.getErrorCode());
    return ResponseEntity
            .status(e.getErrorCode().getStatus())
            .body(response);
  }

  /**
   * Validation 에러 처리
   */
  @ExceptionHandler(BindException.class)
  public ResponseEntity<ErrorResponse> handleBindException(BindException e) {
    log.error("BindException: {}", e.getMessage(), e);

    String message = e.getBindingResult()
            .getAllErrors()
            .get(0)
            .getDefaultMessage();

    ErrorResponse response = ErrorResponse.of(HttpStatus.BAD_REQUEST, message);
    return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(response);
  }

  /**
   * 기타 예외 처리
   */
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleException(Exception e) {
    log.error("Unexpected Exception: {}", e.getMessage(), e);

    ErrorResponse response = ErrorResponse.of(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "서버 내부 오류가 발생했습니다."
    );
    return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(response);
  }
}