package com.siam.auth_demo.service;


import com.siam.auth_demo.dto.AuthResponse;
import com.siam.auth_demo.dto.RegisterRequest;
import com.siam.auth_demo.entity.Role;
import com.siam.auth_demo.entity.User;
import com.siam.auth_demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RedisTokenService redisTokenService;

    public AuthResponse register(RegisterRequest request){
        if(userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exisits");
        }

        var user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        return generateAuthResponse(user);
    }
    public AuthResponse login(LoginRequest request) {
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() => new RuntimeException("Invalid Credential"));
        if(!passwordEncoder.matches(request.getPassword, user.getPassword())) {
            throw new RuntimeException("Invalid Credential");
        }
        return generateAuthResponse(user);
    }

    public AuthResponse refreshToken(String refreshToken) {
        if(!jwtService.isTokenValid(refreshToken)) {
            throw new RuntimeException("Invalid or Expired Refresh Token");
        }
        String userEmail = jwtService.extractEmail(refreshToken);
        String storedToken = redisTokenService.getRefreshToken(userEmail);

        if(storedToken == null || !storedToken.equals(userEmail)) {
            throw new RuntimeException("Invalid Refresh Token");
        }

        var user = userRepository.findByEmail(userEmail)
                                 .orElseThrow(()=> new RuntimeException("User not found"));
        return generateAuthResponse(user);
    }

    public void logout(String email, String accessToken) {
        redisTokenService.deleteRefreshToken(email);
        long remainingTime = jwtService.getAccessTokenExpiration();
        redisTokenService.blacklistToken(accessToken, remainingTime);
        return ;
    }
    public void revokeToken() {
        long remainingTime = jwtService.getAccessTokenExpiration();
        redisTokenService.blacklistToken(accessToken, remainingTime);
    }
    private AuthResponse generateAuthResponse(User user) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshTOken(user);

        redisTokenService.saveRefreshToken(user.getEmail, refreshToken, 604800000L);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpiration()/1000)
                .email(user.getEmail())
                .role(user.getRole().name())
                .build;
    }


}
