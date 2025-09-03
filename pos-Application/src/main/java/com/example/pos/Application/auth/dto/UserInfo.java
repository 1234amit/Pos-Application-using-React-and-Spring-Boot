package com.example.pos.Application.auth.dto;

public class UserInfo {
    private String fullName;
    private String email;

    public UserInfo() {}
    public UserInfo(String fullName, String email) {
        this.fullName = fullName;
        this.email = email;
    }
    public String getFullName() { return fullName; }
    public String getEmail() { return email; }
    public void setFullName(String fullName) { this.fullName = fullName; }
    public void setEmail(String email) { this.email = email; }
}
