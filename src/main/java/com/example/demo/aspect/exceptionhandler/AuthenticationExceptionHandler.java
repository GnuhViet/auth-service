package com.example.demo.aspect.exceptionhandler;

import com.example.demo.aspect.error.ApiError;
import com.example.demo.aspect.error.ApiValidationError;
import com.example.demo.authentication.exceptions.RegisterException;
import com.example.demo.authentication.exceptions.TokenAttemptsException;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Order(0)
@ControllerAdvice
public class AuthenticationExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    protected ResponseEntity<Object> handleBadCredentialsException(BadCredentialsException ex) {
        ApiError apiError = new ApiError(HttpStatus.UNAUTHORIZED);
        apiError.setMessage(ex.getMessage());
        return RestExceptionHandler.buildResponseEntity(apiError);
    }

    @ExceptionHandler(TokenAttemptsException.class)
    protected ResponseEntity<Object> handleTokenAttemptsException(TokenAttemptsException ex) {
        ApiError apiError = new ApiError(HttpStatus.LOCKED);
        apiError.setMessage(ex.getMessage());
        return RestExceptionHandler.buildResponseEntity(apiError);
    }

    @ExceptionHandler(RegisterException.class)
    public ResponseEntity<Object> handleRegisterException(RegisterException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        var apiError = new ApiError(HttpStatus.CONFLICT);
        apiError.setMessage(ex.getMessage());
        apiError.setSubErrors(List.of(new ApiValidationError(errors)));
        return RestExceptionHandler.buildResponseEntity(apiError);
    }
}
