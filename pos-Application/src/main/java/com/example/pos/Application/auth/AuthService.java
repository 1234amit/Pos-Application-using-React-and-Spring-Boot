package com.example.pos.Application.auth;

import com.example.pos.Application.auth.dto.*;
import com.example.pos.Application.configuration.JwtProvider;
import com.example.pos.Application.user.Role;
import com.example.pos.Application.user.User;
import com.example.pos.Application.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authManager;
    private final JwtProvider jwt;

    public AuthService(UserRepository repo, PasswordEncoder encoder, AuthenticationManager authManager, JwtProvider jwt) {
        this.repo = repo;
        this.encoder = encoder;
        this.authManager = authManager;
        this.jwt = jwt;
    }

//    @Transactional
//    public TokenResponse register(RegisterRequest req) {
//        if (repo.existsByEmail(req.getEmail())) throw new IllegalArgumentException("Email already in use");
//        User u = new User();
//        u.setFullName(req.getFullName());
//        u.setEmail(req.getEmail().toLowerCase());
//        u.setPassword(encoder.encode(req.getPassword()));
//        u.setRole(Role.USER);
//        u = repo.save(u);
//        String access = jwt.generateAccessToken(u);
//        String refresh = jwt.generateRefreshToken(u);
////        return new TokenResponse(access, refresh, 60L * 60L * 24L * 30L);
//        return new RegisterResponse("Registration successful", new UserInfo(u.getFullName(), u.getEmail()), access, refresh, ttl);
//
//    }

@Transactional
public RegisterResponse register(RegisterRequest req) {
    if (repo.existsByEmail(req.getEmail())) throw new IllegalArgumentException("Email already in use");
    User u = new User();
    u.setFullName(req.getFullName());
    u.setEmail(req.getEmail().toLowerCase());
    u.setPassword(encoder.encode(req.getPassword()));
    u.setRole(Role.USER);
    u = repo.save(u);
    String access = jwt.generateAccessToken(u);
    String refresh = jwt.generateRefreshToken(u);
    long ttl = 60L * 60L * 24L * 30L;
    return new RegisterResponse("Registration successful", new UserInfo(u.getFullName(), u.getEmail()), access, refresh, ttl);
}

    public TokenResponse login(LoginRequest req) {
        authManager.authenticate(new UsernamePasswordAuthenticationToken(req.getEmail().toLowerCase(), req.getPassword()));
        User u = repo.findByEmail(req.getEmail().toLowerCase()).orElseThrow();
        String access = jwt.generateAccessToken(u);
        String refresh = jwt.generateRefreshToken(u);
        return new TokenResponse(access, refresh, 60L * 60L * 24L * 30L);
    }

    public TokenResponse refresh(RefreshRequest req) {
        var claims = jwt.parseClaims(req.getRefreshToken());
        String type = claims.get("type", String.class);
        if (!"refresh".equals(type)) throw new IllegalArgumentException("Invalid token type");
        String email = claims.getSubject();
        User u = repo.findByEmail(email).orElseThrow();
        String access = jwt.generateAccessToken(u);
        return new TokenResponse(access, req.getRefreshToken(), 60L * 60L * 24L * 30L);
    }
}