package com.example.demo.authentication;

import com.example.demo.authentication.dtos.DetailsAppUserDTO;
import com.example.demo.user.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JWTService {
    private String INJECTED_SECRET_KEY;
    private int JWT_EXPIRATION_MS;
    private int JWT_REFRESH_EXPIRATION_MS;
    private String ISSUER;

    @Autowired
    public JWTService(
            @Value("${app.jwt-secret}") String INJECTED_SECRET_KEY,
            @Value("${app.jwt-expiration-ms}") int JWT_EXPIRATION_MS,
            @Value("${app.jwt-refresh-expiration-ms}") int JWT_REFRESH_EXPIRATION_MS,
            @Value("${app.name}") String ISSUER
    ) {
        this.INJECTED_SECRET_KEY = INJECTED_SECRET_KEY;
        this.JWT_EXPIRATION_MS = JWT_EXPIRATION_MS;
        this.JWT_REFRESH_EXPIRATION_MS = JWT_REFRESH_EXPIRATION_MS;
        this.ISSUER = ISSUER;
    }


    public enum TokenType {
        access,
        refresh
    }

    public class DecodedToken {
        @Getter private final String userId;
        @Getter private final String[] roles;
        @Getter private final Date expiration;
        @Getter private final String issuer;
        @Getter private final Date issuerAt;

        private DecodedToken(Claims claims) throws MalformedJwtException {

            @SuppressWarnings("unchecked")
            List<String> rawRoles = (List<String>) claims.get("roles");

            userId = claims.getSubject();
            expiration = claims.getExpiration();
            issuer = claims.getIssuer();
            issuerAt = claims.getIssuedAt();

            if (rawRoles != null) {
                roles = rawRoles.toArray(new String[0]);
            } else {
                roles = null;
            }
        }
    }

    public DecodedToken decodeToken(String token) throws MalformedJwtException{
        return new DecodedToken(extractAllClaims(token));
    }

    @Deprecated
    public boolean isTokenValid(String token) {

        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();

            if (isTokenExpired(token)) {
                return false;
            }
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            return false;
        }

        return true;
    }

    @Deprecated
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    @Deprecated
    public String extractId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Deprecated
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    @Deprecated
    public String[] extractRoles(String token) {
        Claims claims = extractAllClaims(token);
        List<String> rolesList = (List<String>) extractClaim(claims, "roles");
        return rolesList.toArray(new String[0]);
    }

    @Deprecated
    public Object extractClaim(Claims claims, String claimName) {
        return claims.get(claimName);
    }

    @Deprecated
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) throws MalformedJwtException {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String generateAccessToken(DetailsAppUserDTO user) {
        return generateToken(
                user.getId(),
                Map.of("roles", user.getRoles().stream()
                        .map(Role::getName)
                        .collect(Collectors.toList())
                ),
                TokenType.access
        );
    }

    public String generateRefreshToken(DetailsAppUserDTO user) {
        return generateToken(user.getId(), Collections.emptyMap(), TokenType.refresh);
    }

    public String generateToken(
            String subject,
            Map<String, Object> extraClaims,
            TokenType type

    ) {
        int expirationMs;
        switch (type) {
            case access -> expirationMs = JWT_EXPIRATION_MS;
            case refresh -> expirationMs = JWT_REFRESH_EXPIRATION_MS;
            default -> expirationMs = 0;
        }

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(subject)
                .setIssuer(ISSUER)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKey() {
        return Keys.hmacShaKeyFor(Objects.requireNonNull(INJECTED_SECRET_KEY).getBytes(StandardCharsets.UTF_8));
    }
}
