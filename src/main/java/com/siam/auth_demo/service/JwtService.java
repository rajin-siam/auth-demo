package com.siam.auth_demo.service;

import com.siam.auth_demo.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Data
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Generate access token
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getRole().name());
        claims.put("userId", user.getId());
        claims.put("type", "access");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getEmail())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    // Generate refresh token
    public String generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");

        return Jwts.builder()
                .claims(claims)
                .subject(user.getEmail())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(getSigningKey())
                .compact();
    }

    // Get email from token
    public String getEmailFromToken(String token) {
        return parseToken(token).getSubject();
    }

    // Extract email (alias for getEmailFromToken for consistency)
    public String extractEmail(String token) {
        return getEmailFromToken(token);
    }

    // Get role from token
    public String getRoleFromToken(String token) {
        return parseToken(token).get("role", String.class);
    }

    // Get user ID from token
    public Long getUserIdFromToken(String token) {
        return parseToken(token).get("userId", Long.class);
    }

    // Validate token
    public boolean isTokenValid(String token) {
        try {
            Claims claims = parseToken(token);
            Date expiration = claims.getExpiration();
            return expiration.after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    // Check if token is refresh token
    public boolean isRefreshToken(String token) {
        try {
            String type = parseToken(token).get("type", String.class);
            return "refresh".equals(type);
        } catch (Exception e) {
            return false;
        }
    }

    // Check if token is access token
    public boolean isAccessToken(String token) {
        try {
            String type = parseToken(token).get("type", String.class);
            return "access".equals(type);
        } catch (Exception e) {
            return false;
        }
    }


    // Parse the token and get all claims
    private Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}