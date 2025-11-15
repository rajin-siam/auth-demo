package com.siam.auth_demo.service;


import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisTokenService {
    private final RedisTemplate<String, String> redisTemplate;
    private static final String BLACKLIST_PREFIX = "blacklist::access:";

    public void blacklistAccessToken(String accessToken, long expirationMs) {
        String key = BLACKLIST_PREFIX + accessToken;
        redisTemplate.opsForValue().set(key, "revoked", expirationMs, TimeUnit.MILLISECONDS);
    }

    public boolean isAccessTokenBlacklisted(String accessToken) {
        String key = BLACKLIST_PREFIX + accessToken;
        return redisTemplate.hasKey(key);
    }
}
