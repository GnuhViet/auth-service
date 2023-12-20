package com.example.demo.authentication.exceptions;

import lombok.Getter;

@Getter
public class TokenAttemptsException extends RuntimeException{
    private final String message;

    public TokenAttemptsException(String message) {
        this.message = message;
    }
}
