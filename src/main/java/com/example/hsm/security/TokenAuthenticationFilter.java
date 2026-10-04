package com.example.hsm.security;

import com.example.hsm.entity.HsmUser;
import com.example.hsm.repository.HsmUserRepository;
import com.example.hsm.service.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Extracts and validates the Bearer token from every request.
 * Identical 401 response for missing, bad, or disabled-user tokens — no oracle.
 */
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final HsmUserRepository userRepository;
    private final TokenService tokenService;
    private final ObjectMapper objectMapper;

    public TokenAuthenticationFilter(HsmUserRepository userRepository,
                                     TokenService tokenService,
                                     ObjectMapper objectMapper) {
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            if (!token.isBlank()) {
                String prefix = tokenService.extractPrefix(token);
                Optional<HsmUser> maybeUser = userRepository.findByTokenPrefix(prefix);
                if (maybeUser.isPresent()) {
                    HsmUser user = maybeUser.get();
                    if (user.isEnabled() && tokenService.verifyToken(token, user.getTokenHash())) {
                        HsmPrincipal principal = new HsmPrincipal(user.getId(), user.getUsername(), user.getRole());
                        String authority = "ROLE_" + user.getRole().name();
                        var auth = new UsernamePasswordAuthenticationToken(
                                principal, null, List.of(new SimpleGrantedAuthority(authority)));
                        SecurityContextHolder.getContext().setAuthentication(auth);
                        filterChain.doFilter(request, response);
                        return;
                    }
                }
            }
            // Token present but invalid — reject immediately, identical message regardless of reason
            sendUnauthorized(response, request.getRequestURI());
            return;
        }
        // No token — let downstream security decide (protected paths will reject)
        filterChain.doFilter(request, response);
    }

    private void sendUnauthorized(HttpServletResponse response, String path) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), Map.of(
                "timestamp", Instant.now().toString(),
                "status", 401,
                "error", "Unauthorized",
                "message", "Authentication required",
                "path", path
        ));
    }
}
