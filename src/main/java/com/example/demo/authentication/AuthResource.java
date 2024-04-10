package com.example.demo.authentication;

import com.example.demo.authentication.model.AuthenticationRequest;
import com.example.demo.authentication.model.AuthenticationResponse;
import com.example.demo.authentication.model.RefreshRequest;
import com.example.demo.authentication.model.RegisteredRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthResource {
    private final AuthService authService;

    @PostMapping("/register")
    @Operation(summary = "User register, Role: All")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisteredRequest request) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(authService.register(request));
    }

    @PostMapping("/login")
    @Operation(summary = "login , Role: All")
    public ResponseEntity<AuthenticationResponse> authenticate(@Valid @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @PostMapping("/refresh")
    @Operation(summary = "refresh jwt token , Role: All")
    public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/email/validate")
    @Operation(summary = "Send email validation token, Role: all", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Void> emailConfirm(Principal principal) {
        authService.sendConfirmToken(principal.getName());
        return ResponseEntity.status(HttpStatus.OK).build();
    }

    @PostMapping("/email/confirm")
    @Operation(summary = "Email validation, Role: all", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Void> validateEmailToken(@RequestParam String token, Principal principal) {
        if (authService.validateEmailToken(token, principal.getName())) {
            return ResponseEntity.status(HttpStatus.OK).build();
        } else {
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).build();
        }
    }
}
