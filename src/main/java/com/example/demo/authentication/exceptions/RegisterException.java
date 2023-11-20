package com.example.demo.authentication.exceptions;

import lombok.Getter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;

public class RegisterException extends AuthenticationException {
    @Getter
    private BindingResult bindingResult;

    public RegisterException(String message, BindingResult bindingResult) {
        super(message);
        this.bindingResult = bindingResult;
    }
}
