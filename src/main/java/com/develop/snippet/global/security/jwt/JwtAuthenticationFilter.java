package com.develop.snippet.global.security.jwt;

import com.develop.snippet.domain.user.domain.UserRole;
import com.develop.snippet.global.security.principal.UserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            // 1. Request Header에서 JWT 추출
            String jwt = getJwtFromRequest(request);

            // 2. JWT 검증
            if (StringUtils.hasText(jwt) && jwtProvider.validateToken(jwt)) {

                // 3. Access Token인지 확인
                if (!jwtProvider.isAccessToken(jwt)) {
                    log.warn("Refresh Token cannot be used for authentication");
                    filterChain.doFilter(request, response);
                    return;
                }

                // 4. JWT에서 사용자 정보 추출
                Long userId = jwtProvider.getUserId(jwt);
                String email = jwtProvider.getEmail(jwt);
                UserRole role = jwtProvider.getRole(jwt);

                // 5. UserPrincipal 생성
                UserPrincipal userPrincipal = new UserPrincipal(userId, email, role);

                // 6. Authentication 객체 생성
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userPrincipal,
                                null,
                                userPrincipal.getAuthorities()
                        );

                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // 7. SecurityContext에 인증 정보 설정
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("Set Authentication to security context for '{}', uri: {}",
                        email, request.getRequestURI());
            }
        } catch (Exception e) {
            log.error("Could not set user authentication in security context", e);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Request Header에서 JWT 추출
     * Authorization: Bearer {token}
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }
}