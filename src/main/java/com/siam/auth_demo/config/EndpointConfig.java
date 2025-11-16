package com.siam.auth_demo.config;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class EndpointConfig {

    // Public endpoints (no authentication required)
    public List<String> getPublicEndpoints() {
        return List.of(
                "/api/auth/**",
                "/api/public/**"
        );
    }

    // Admin endpoints (ROLE_ADMIN required)
    public List<String> getAdminEndpoints() {
        return List.of(
                "/api/admin/**"
        );
    }

    // User endpoints (authenticated users only)
    public List<String> getUserEndpoints() {
        return List.of(
                "/api/user/**"
        );
    }
}
