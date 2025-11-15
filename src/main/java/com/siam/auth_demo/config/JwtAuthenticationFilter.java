package com.siam.auth_demo.config;

import com.siam.auth_demo.service.JwtService;
import com.siam.auth_demo.service.RedisTokenService;
import io.lettuce.core.dynamic.annotation.CommandNaming;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import reactor.util.annotation.NonNull;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final RedisTokenService redisTokenService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            String accessToken = authHeader.substring(7);

            if(redisTokenService.isAccessTokenBlacklisted(accessToken)) {
                response.setStatus();
            }
        }


    }
}
