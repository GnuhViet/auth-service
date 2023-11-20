package com.example.demo.authentication.exceptions;

import lombok.Getter;

@Getter
public class EmptyRequestBodyException extends RuntimeException{
    private final String message;

    public EmptyRequestBodyException(String message) {
        this.message = message;
    }
}
