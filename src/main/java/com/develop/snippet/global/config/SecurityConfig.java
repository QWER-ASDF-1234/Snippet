package com.develop.snippet.global.config;

import com.develop.snippet.global.security.handler.JwtAccessDeniedHandler;
import com.develop.snippet.global.security.handler.JwtAuthenticationEntryPoint;
import com.develop.snippet.global.security.jwt.JwtAuthenticationFilter;
import com.develop.snippet.global.security.oauth.CustomOAuth2UserService;
import com.develop.snippet.global.security.oauth.OAuth2FailureHandler;
import com.develop.snippet.global.security.oauth.OAuth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final CustomOAuth2UserService customOAuth2UserService;
  private final OAuth2SuccessHandler oAuth2SuccessHandler;
  private final OAuth2FailureHandler oAuth2FailureHandler;
  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            // CORS 설정 (중요!)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // CSRF 비활성화 (JWT 사용)
            .csrf(AbstractHttpConfigurer::disable)

            // 세션 사용하지 않음 (Stateless)
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // 예외 처리
            .exceptionHandling(exception -> exception
                    .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                    .accessDeniedHandler(jwtAccessDeniedHandler)
            )

            // 요청 인가 설정
            .authorizeHttpRequests(auth -> auth
                    // 공개 엔드포인트
                    .requestMatchers(
                            "/",
                            "/error",
                            "/favicon.ico"
                    ).permitAll()

                    // 테스트 엔드포인트 (임시)
                    .requestMatchers(
                            "/test/**",
                            "/api/health"
                    ).permitAll()

                    // OAuth2 로그인 관련
                    .requestMatchers(
                            "/login/**",
                            "/oauth2/**"
                    ).permitAll()

                    // Auth API (토큰 재발급, 로그아웃)
                    .requestMatchers(
                            "/api/auth/refresh",
                            "/api/auth/logout"
                    ).permitAll()

                    // Admin 전용
                    .requestMatchers("/api/admin/**").hasRole("ADMIN")

                    // 나머지는 인증 필요
                    .anyRequest().authenticated()
            )

            // OAuth2 로그인 설정
            .oauth2Login(oauth2 -> oauth2
                    .userInfoEndpoint(userInfo ->
                            userInfo.oidcUserService(customOAuth2UserService::loadUser)
                    )
                    .successHandler(oAuth2SuccessHandler)
                    .failureHandler(oAuth2FailureHandler)
            )

            // JWT 인증 필터 추가
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  /**
   * CORS 설정
   */
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    return request -> {
      CorsConfiguration config = new CorsConfiguration();
      config.setAllowedOrigins(List.of("http://localhost:5173"));
      config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
      config.setAllowedHeaders(List.of("*"));
      config.setAllowCredentials(true);
      config.setMaxAge(3600L);

      System.out.println("CORS Config Applied for: " + request.getRequestURI());

      return config;
    };
  }
}