package com.develop.snippet.global.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

  private boolean success;
  private T data;
  private String message;

  public static <T> ApiResponse<T> success(T data) {
    return new ApiResponse<>(true, data, null);
  }

  public static <T> ApiResponse<T> success(T data, String message) {
    return new ApiResponse<>(true, data, message);
  }

  public static <T> ApiResponse<T> error(String message) {
    return new ApiResponse<>(false, null, message);
  }
}