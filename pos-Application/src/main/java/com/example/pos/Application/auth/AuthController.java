package com.example.pos.Application.auth;

import com.example.pos.Application.auth.dto.LoginRequest;
import com.example.pos.Application.auth.dto.RefreshRequest;
import com.example.pos.Application.auth.dto.RegisterRequest;
import com.example.pos.Application.auth.dto.RegisterResponse;
import com.example.pos.Application.auth.dto.TokenResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService service;

    public AuthController(AuthService service) {
        this.service = service;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest req) {
        return ResponseEntity.status(201).body(service.register(req));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest req) {
        return ResponseEntity.ok(service.login(req));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshRequest req) {
        return ResponseEntity.ok(service.refresh(req));
    }
}
