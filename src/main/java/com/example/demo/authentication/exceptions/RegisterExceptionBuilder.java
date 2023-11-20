package com.example.demo.authentication.exceptions;

import lombok.Getter;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;

import java.util.ArrayList;
import java.util.List;

public class RegisterExceptionBuilder {
    @Getter private final List<FieldError> fieldErrors = new ArrayList<>();
    private String message;

    public RegisterExceptionBuilder addFieldError(String field, String code, String message) {
        fieldErrors.add(new FieldError("registeredRequest", field, code, false, null, null, message));
        return this;
    }

    public RegisterExceptionBuilder message(String message) {
        this.message = message;
        return this;
    }

    public RegisterException build() {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(null, null);
        fieldErrors.forEach(bindingResult::addError);
        return new RegisterException(message, bindingResult);
    }

    public boolean isEmptyError() {
        return fieldErrors.isEmpty();
    }
}
