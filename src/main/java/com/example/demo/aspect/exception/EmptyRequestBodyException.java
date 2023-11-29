package com.example.demo.aspect.exception;

import lombok.Getter;

@Getter
public class EmptyRequestBodyException extends RuntimeException{
    private final String message;

    public EmptyRequestBodyException(String message) {
        this.message = message;
    }
}
