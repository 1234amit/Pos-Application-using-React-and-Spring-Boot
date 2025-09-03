package com.example.pos.Application.auth.dto;

public class RegisterResponse {
    private String message;
    private UserInfo user;
    private String tokenType = "Bearer";
    private String accessToken;
    private String refreshToken;
    private long expiresInSeconds;

    public RegisterResponse() {}
    public RegisterResponse(String message, UserInfo user, String accessToken, String refreshToken, long expiresInSeconds) {
        this.message = message;
        this.user = user;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresInSeconds = expiresInSeconds;
    }
    public String getMessage() { return message; }
    public UserInfo getUser() { return user; }
    public String getTokenType() { return tokenType; }
    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public long getExpiresInSeconds() { return expiresInSeconds; }
    public void setMessage(String message) { this.message = message; }
    public void setUser(UserInfo user) { this.user = user; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    public void setExpiresInSeconds(long expiresInSeconds) { this.expiresInSeconds = expiresInSeconds; }
}
