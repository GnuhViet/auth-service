package com.example.demo.user.exceptions;

import lombok.Getter;

@Getter
public class UserAlreadyHaveRoleException extends RuntimeException{
    private final String message;

    public UserAlreadyHaveRoleException(String message) {
        this.message = message;
    }
}
