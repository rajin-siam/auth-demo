package com.siam.auth_demo.controller;


import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/user/profile")
    public ResponseEntity<Map<String, String>> getUserProfile(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "User profile",
                "email", authentication.getName()
        ));
    }

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> getAdminDashboard(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "Admin dashboard",
                "email", authentication.getName()
        ));
    }

    @GetMapping("/public/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "UP"));
    }
}
