package com.beaconnavigator.api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String PREFIX = "Bearer ";
    private static final String COOKIE_NAME = "access_token";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1) Tenta pegar do header Authorization: Bearer <token>
        String token = extractFromAuthorizationHeader(request);

        // 2) Se não veio no header, tenta pegar do cookie access_token
        if (token == null) {
            token = extractFromCookie(request, COOKIE_NAME);
        }

        // 3) Valida e autentica
        if (token != null && jwtService.isTokenValid(token)) {
            String subject = jwtService.extractSubject(token);

            var auth = new UsernamePasswordAuthenticationToken(
                    subject,
                    null,
                    Collections.emptyList()
            );

            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }

    private String extractFromAuthorizationHeader(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) return null;

        if (!header.startsWith(PREFIX)) return null;

        String token = header.substring(PREFIX.length()).trim();
        return token.isBlank() ? null : token;
    }

    private String extractFromCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) return null;

        for (Cookie c : cookies) {
            if (cookieName.equals(c.getName())) {
                String value = c.getValue();
                return (value == null || value.isBlank()) ? null : value.trim();
            }
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        // Preflight
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) return true;

        // Públicas
        if ("/auth/login".equals(path)) return true;
        if ("/usuarios".equals(path) && "POST".equalsIgnoreCase(request.getMethod())) return true;
        if ("/usuarios/teste".equals(path)) return true;

        // Swagger
        if (path.startsWith("/swagger-ui")) return true;
        if (path.startsWith("/v3/api-docs")) return true;

        // OAuth2 endpoints (não filtrar pra não atrapalhar o login)
        if (path.startsWith("/oauth2")) return true;
        if (path.startsWith("/login/oauth2")) return true;

        // Actuator (se você usa healthcheck público)
        if (path.startsWith("/actuator/health")) return true;

        return false;
    }
}
