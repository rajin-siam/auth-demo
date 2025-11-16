package com.siam.auth_demo.service;

import com.siam.auth_demo.entity.RefreshToken;
import com.siam.auth_demo.entity.User;
import com.siam.auth_demo.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private static final SecureRandom secureRandom = new SecureRandom();

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    /**
     * Generate a random refresh token string
     */
    private String generateRandomToken() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Create a new refresh token for a user
     */
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Delete existing refresh token for this user (one-to-one relationship)
        refreshTokenRepository.findByUser(user).ifPresent(refreshTokenRepository::delete);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(generateRandomToken())
                .user(user)
                .expirationDate(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .createdAt(LocalDateTime.now())
                .isRevoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Validate and retrieve refresh token
     */
    public RefreshToken validateRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (refreshToken.isRevoked()) {
            throw new RuntimeException("Refresh token has been revoked");
        }

        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token has expired");
        }

        return refreshToken;
    }

    /**
     * Revoke refresh token for a user
     */
    @Transactional
    public void revokeUserRefreshToken(User user) {
        refreshTokenRepository.findByUser(user).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        });
    }

    /**
     * Delete refresh token for a user
     */
    @Transactional
    public void deleteUserRefreshToken(User user) {
        refreshTokenRepository.deleteByUser(user);
    }

    /**
     * Delete expired tokens (for cleanup jobs)
     */
    @Transactional
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteByExpirationDateBefore(LocalDateTime.now());
    }

    /**
     * Get refresh token by user
     */
    public RefreshToken getRefreshTokenByUser(User user) {
        return refreshTokenRepository.findByUser(user).orElse(null);
    }
}