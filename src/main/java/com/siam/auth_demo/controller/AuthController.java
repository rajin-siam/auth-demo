package com.siam.auth_demo.controller;

import com.siam.auth_demo.dto.AuthResponse;
import com.siam.auth_demo.dto.LoginRequest;
import com.siam.auth_demo.dto.RefreshTokenRequest;
import com.siam.auth_demo.dto.RegisterRequest;
import com.siam.auth_demo.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request.getRefreshToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            Authentication authentication,
            @RequestHeader("Authorization") String authHeader
    ) {
        String token = authHeader.substring(7);
        authService.logout(authentication.getName(), token);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @PostMapping("/revoke")
    public ResponseEntity<Map<String, String>> revokeToken(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7);
        authService.revokeToken(token);
        return ResponseEntity.ok(Map.of("message", "Token revoked successfully"));
    }
}