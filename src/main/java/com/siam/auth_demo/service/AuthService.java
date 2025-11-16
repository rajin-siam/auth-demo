package com.siam.auth_demo.service;

import com.siam.auth_demo.dto.AuthResponse;
import com.siam.auth_demo.dto.LoginRequest;
import com.siam.auth_demo.dto.RegisterRequest;
import com.siam.auth_demo.entity.RefreshToken;
import com.siam.auth_demo.entity.Role;
import com.siam.auth_demo.entity.User;
import com.siam.auth_demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RedisTokenService redisTokenService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        var user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        userRepository.save(user);

        return generateAuthResponse(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        return generateAuthResponse(user);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenString) {
        // Validate the refresh token from database
        RefreshToken refreshToken = refreshTokenService.validateRefreshToken(refreshTokenString);

        User user = refreshToken.getUser();

        // Generate new access token
        String newAccessToken = jwtService.generateAccessToken(user);

        // Optionally rotate refresh token (more secure)
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpiration() / 1000)
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }

    @Transactional
    public void logout(String email, String accessToken) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Delete refresh token from database
        refreshTokenService.deleteUserRefreshToken(user);

        // Blacklist the access token in Redis
        long remainingTime = jwtService.getRemainingExpirationTime(accessToken);
        if (remainingTime > 0) {
            redisTokenService.blacklistToken(accessToken, remainingTime);
        }
    }

    public void revokeToken(String accessToken) {
        long remainingTime = jwtService.getRemainingExpirationTime(accessToken);
        if (remainingTime > 0) {
            redisTokenService.blacklistToken(accessToken, remainingTime);
        }
    }

    private AuthResponse generateAuthResponse(User user) {
        // Generate access token (JWT)
        String accessToken = jwtService.generateAccessToken(user);

        // Generate refresh token (random string stored in database)
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpiration() / 1000)
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }
}