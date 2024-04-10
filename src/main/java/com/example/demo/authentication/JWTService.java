package com.example.demo.authentication;

import com.example.demo.authentication.dtos.DetailsAppUserDTO;
import com.example.demo.user.entities.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JWTService {
    private String INJECTED_SECRET_KEY;
    private int JWT_EXPIRATION_MS;
    private int JWT_REFRESH_EXPIRATION_MS;
    private String JWT_ALG;
    private int RSA_KEY_LENGTH;
    private String ISSUER;

    private KeyPair rsaSignKey;
    private Key hs256SignKey;

    @Autowired
    public JWTService(
            @Value("${app.jwt-secret}") String INJECTED_SECRET_KEY,
            @Value("${app.jwt-expiration-ms}") int JWT_EXPIRATION_MS,
            @Value("${app.jwt-refresh-expiration-ms}") int JWT_REFRESH_EXPIRATION_MS,
            @Value("${app.jwt-alg}") String JWT_ALG,
            @Value("${app.rsa-key-length}") int RSA_KEY_LENGTH,
            @Value("${app.name}") String ISSUER
    ) {
        this.INJECTED_SECRET_KEY = INJECTED_SECRET_KEY;
        this.JWT_EXPIRATION_MS = JWT_EXPIRATION_MS;
        this.JWT_REFRESH_EXPIRATION_MS = JWT_REFRESH_EXPIRATION_MS;
        this.JWT_ALG = JWT_ALG;
        this.RSA_KEY_LENGTH = RSA_KEY_LENGTH;
        this.ISSUER = ISSUER;
        rsaSignKey = getRSASignKey();
        hs256SignKey = getHS256SignKey();
    }

    public enum TokenType {
        access,
        refresh
    }

    @Getter
    public static class DecodedToken {
        private final String userId;
        private final String[] roles;
        private final Date expiration;
        private final String issuer;
        private final Date issuerAt;

        private DecodedToken(Claims claims) throws MalformedJwtException {

            @SuppressWarnings("unchecked")
            var rawRoles = (List<String>) claims.get("roles");

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
            getJwtParserBuilder()
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
        return getJwtParserBuilder()
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

        return getJwtBuilder()
                .setClaims(extraClaims)
                .setSubject(subject)
                .setIssuer(ISSUER)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .compact();
    }

    private JwtBuilder getJwtBuilder() {
        if ("RSA".equals(JWT_ALG)) {
            return Jwts.builder()
                    .signWith(rsaSignKey.getPrivate(), SignatureAlgorithm.RS256);
        }
        if ("HS256".equals(JWT_ALG)) {
            return Jwts.builder()
                    .signWith(hs256SignKey, SignatureAlgorithm.HS256);
        }
        throw new IllegalArgumentException("Invalid JWT_ALG");
    }

    private JwtParserBuilder getJwtParserBuilder() {
        if ("RSA".equals(JWT_ALG)) {
            return Jwts.parserBuilder()
                    .setSigningKey(rsaSignKey.getPublic());
        }
        if ("HS256".equals(JWT_ALG)) {
            return Jwts.parserBuilder()
                    .setSigningKey(hs256SignKey);
        }
        throw new IllegalArgumentException("Invalid JWT_ALG");
    }

    private KeyPair getRSASignKey() {
        try {
            var keyGen = KeyPairGenerator.getInstance(JWT_ALG);
            keyGen.initialize(RSA_KEY_LENGTH);
            return keyGen.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private Key getHS256SignKey() {
        return Keys.hmacShaKeyFor(Objects.requireNonNull(INJECTED_SECRET_KEY).getBytes(StandardCharsets.UTF_8));
    }
}
