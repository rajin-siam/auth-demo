package com.siam.auth_demo.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "RefreshToken", unique = true, nullable = false)
    private String refreshToken;
    @Column(name = "Expiration", nullable = false)
    private LocalDateTime
}
