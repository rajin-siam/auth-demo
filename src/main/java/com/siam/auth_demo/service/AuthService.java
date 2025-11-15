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

    private AuthResponse generateAuthResponse(User user) {
        String accessToken = jwtService.createAccessToken(user);
        String refreshToken = jwtService.createRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpiration()/1000)
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();

    }
}
