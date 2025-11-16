package com.siam.auth_demo.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    private static final String BLACKLIST_PREFIX = "blacklist:access:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh:";

    // Blacklist an access token
    public void blacklistToken(String accessToken, long expirationMs) {
        String key = BLACKLIST_PREFIX + accessToken;
        redisTemplate.opsForValue().set(key, "revoked", expirationMs, TimeUnit.MILLISECONDS);
    }

    // Check if access token is blacklisted
    public boolean isAccessTokenBlacklisted(String accessToken) {
        String key = BLACKLIST_PREFIX + accessToken;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // Save refresh token
    public void saveRefreshToken(String userEmail, String refreshToken, long expirationMs) {
        String key = REFRESH_TOKEN_PREFIX + userEmail;
        redisTemplate.opsForValue().set(key, refreshToken, expirationMs, TimeUnit.MILLISECONDS);
    }

    // Get refresh token by user email
    public String getRefreshToken(String userEmail) {
        String key = REFRESH_TOKEN_PREFIX + userEmail;
        return redisTemplate.opsForValue().get(key);
    }

    // Delete refresh token (for logout)
    public void deleteRefreshToken(String userEmail) {
        String key = REFRESH_TOKEN_PREFIX + userEmail;
        redisTemplate.delete(key);
    }
}