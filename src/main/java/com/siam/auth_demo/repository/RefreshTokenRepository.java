package com.siam.auth_demo.repository;

import com.siam.auth_demo.entity.RefreshToken;
import com.siam.auth_demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    Optional<RefreshToken> findByUser(User user);
    void deleteByUser(User user);
    void deleteByExpirationDateBefore(LocalDateTime date);
}