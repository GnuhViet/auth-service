package com.example.demo.authentication;

import com.example.demo.authentication.dtos.DetailsAppUserDTO;
import com.example.demo.authentication.dtos.SimpleAppUserDTO;
import com.example.demo.authentication.exceptions.RegisterExceptionBuilder;
import com.example.demo.authentication.model.*;
import com.example.demo.user.AppUser;
import com.example.demo.user.Constants;
import com.example.demo.user.UserService;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisteredRequest request) throws AuthenticationException {
        RegisterExceptionBuilder exceptionBuilder = new RegisterExceptionBuilder();

        if (userService.existByUsername(request.getUsername())) {
            exceptionBuilder.addFieldError("username", "username.exists", "Username already exists");
        }
        // if exist by email...

        if (!exceptionBuilder.isEmptyError()) {
            throw exceptionBuilder
                    .message("register credentials conflict")
                    .build();
        }

        AppUser user = AppUser.builder()
                .fullName(request.getFullName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        try {
            userService.saveUser(user);
            userService.addRoleToUser(user.getUsername(), Constants.ROLE_USER);
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        return generateToken(userService.getUserid(request.getUsername()));
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) throws AuthenticationException {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        return generateToken(userService.getUserid(request.getUsername()));
    }

    public AuthenticationResponse refreshToken(RefreshRequest request) throws MalformedJwtException {

        final JWTService.DecodedToken refreshToken = jwtService.decodeToken(request.getRefreshToken());
        DetailsAppUserDTO user = userService.getUserDto(refreshToken.getUserId(), DetailsAppUserDTO.class);

        return AuthenticationResponse.builder()
                .accessToken(jwtService.generateAccessToken(user))
                .refreshToken(request.getRefreshToken())
                .build();
    }

    private AuthenticationResponse generateToken(String userId) {
        DetailsAppUserDTO user = userService.getUserDto(userId, DetailsAppUserDTO.class);

        return AuthenticationResponse.builder()
                .accessToken(jwtService.generateAccessToken(user))
                .refreshToken(jwtService.generateRefreshToken(user))
                .build();
    }

    public void changePassword(ChangePasswordRequest request, String userId) throws AuthenticationException {
        String username = userService.getUserDto(userId, SimpleAppUserDTO.class).getUsername();
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        username,
                        request.getOldPassword()
                )
        );

        userService.updateUserPassword(passwordEncoder.encode(request.getNewPassword()), username);
    }

}
