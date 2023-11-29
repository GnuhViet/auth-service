package com.example.demo.filter;

import com.example.demo.authentication.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    public static final int TOKEN_START_IDX = 7; //"Bearer "

    private final Set<String> skipUrls = Set.of(
            "/api/v1/auth/register",
            "/api/v1/auth/authenticate"
    );
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final JWTService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String autHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String token;

        if (autHeader == null || !autHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        token = autHeader.substring(TOKEN_START_IDX);

        try {
            JWTService.DecodedToken decodedToken = jwtService.decodeToken(token);
            if (decodedToken.getUserId() == null || decodedToken.getRoles() == null) {
                filterChain.doFilter(request, response);
                return;
            }

            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            Arrays.stream(decodedToken.getRoles()).forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role));
            });
            Authentication authenticationToken = new UsernamePasswordAuthenticationToken(decodedToken.getUserId(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        } catch (Exception e) {
            log.error(e.getMessage());
            response.setHeader(HttpHeaders.WARNING, e.getMessage());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());

        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return skipUrls.stream().anyMatch(p -> pathMatcher.match(p, request.getRequestURI()));
    }
}
