package com.example.demo.authentication;

import com.example.demo.authentication.dtos.DetailsAppUserDTO;
import com.example.demo.authentication.dtos.SimpleAppUserDTO;
import com.example.demo.authentication.entities.ConfirmToken;
import com.example.demo.authentication.exceptions.RegisterExceptionBuilder;
import com.example.demo.authentication.exceptions.TokenAttemptsException;
import com.example.demo.authentication.model.*;
import com.example.demo.authentication.repo.ConfirmTokenRepo;
import com.example.demo.email.EmailSender;
import com.example.demo.email.EmailService;
import com.example.demo.user.constans.UserStatus;
import com.example.demo.user.entities.AppUser;
import com.example.demo.user.constans.UserRoles;
import com.example.demo.user.UserService;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private static final int CONFIRM_TOKEN_LENGTH = 6;
    private static final int TOKEN_EXPIRED_MINUTE = 15;
    private final UserService userService;
    private final ConfirmTokenRepo tokenRepo;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailSender emailSender;

    public AuthenticationResponse register(RegisteredRequest request) throws AuthenticationException {
        RegisterExceptionBuilder exceptionBuilder = new RegisterExceptionBuilder();

        if (userService.existByUsername(request.getUsername())) {
            exceptionBuilder.addFieldError("username", "username.exists", "Username already exists");
        }
        // if exist by email...
        if (userService.existByEmail(request.getEmail())) {
            exceptionBuilder.addFieldError("email", "email.used", "Email has been use");
        }

        if (!exceptionBuilder.isEmptyError()) {
            throw exceptionBuilder
                    .message("register credentials conflict")
                    .build();
        }

        AppUser user = AppUser.builder()
                .fullName(request.getFullName())
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .status(UserStatus.Inactive.name())
                .build();

        ConfirmToken token = generateConfirmToken(user);
        log.info(token.getToken());

        try {
            userService.saveUser(user);
            userService.addRoleToUser(user.getUsername(), UserRoles.ROLE_USER);
            tokenRepo.save(token);
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        return generateJWTToken(userService.getUserid(request.getUsername()));
    }

    @Transactional
    public void sendConfirmToken(String userID) {
        ConfirmToken dbToken = tokenRepo
                .findByAppUser_Id(userID).orElseThrow();
        tokenRepo.delete(dbToken);
        tokenRepo.flush();


        ConfirmToken token = generateConfirmToken(userService.getReferenceById(userID));
        tokenRepo.save(token);
        log.info("new token send: " + token.getToken());

        String email = userService.getUserEmail(userID);

        emailSender.send(email, token.getToken());
    }

    @Transactional(noRollbackFor = TokenAttemptsException.class)
    public boolean validateEmailToken(String requestToken, String userID) {

        ConfirmToken dbToken = tokenRepo
                .findByAppUser_Id(userID).orElseThrow(() -> new TokenAttemptsException("Please resend token"));

        if (!dbToken.getToken().equals(requestToken)) {
            if (dbToken.getAttempts() > 5) {
                tokenRepo.delete(dbToken);
                throw new TokenAttemptsException("Please resend token");
            }
            dbToken.setAttempts(dbToken.getAttempts() + 1);
            return false;
        }

        userService.setUserActive(userID);
        tokenRepo.delete(dbToken);
        return true;
    }

    private static ConfirmToken generateConfirmToken(AppUser user) {

        StringBuilder sb = new StringBuilder(CONFIRM_TOKEN_LENGTH);
        new Random().ints(CONFIRM_TOKEN_LENGTH, 0, 10).forEach(sb::append);

        return ConfirmToken.builder()
                .token(sb.toString())
                .createAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(TOKEN_EXPIRED_MINUTE))
                .attempts(0)
                .appUser(user)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) throws AuthenticationException {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        return generateJWTToken(userService.getUserid(request.getUsername()));
    }

    public AuthenticationResponse refreshToken(RefreshRequest request) throws MalformedJwtException {

        final JWTService.DecodedToken refreshToken = jwtService.decodeToken(request.getRefreshToken());
        DetailsAppUserDTO user = userService.getUserDto(refreshToken.getUserId(), DetailsAppUserDTO.class);

        return AuthenticationResponse.builder()
                .accessToken(jwtService.generateAccessToken(user))
                .refreshToken(request.getRefreshToken())
                .build();
    }

    private AuthenticationResponse generateJWTToken(String userId) {
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
