package com.example.hsm.config;

import com.example.hsm.repository.HsmUserRepository;
import com.example.hsm.security.TokenAuthenticationFilter;
import com.example.hsm.service.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;
import java.util.Map;

/** Spring Security configuration for stateless token-based authentication. */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final HsmUserRepository userRepository;
    private final TokenService tokenService;
    private final ObjectMapper objectMapper;

    public SecurityConfig(HsmUserRepository userRepository,
                          TokenService tokenService,
                          ObjectMapper objectMapper) {
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.objectMapper = objectMapper;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .formLogin(fl -> fl.disable())
            .httpBasic(hb -> hb.disable())
            .addFilterBefore(new TokenAuthenticationFilter(userRepository, tokenService, objectMapper),
                    UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html",
                    "/actuator/health"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, e) -> {
                    response.setStatus(401);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    objectMapper.writeValue(response.getWriter(), Map.of(
                        "timestamp", Instant.now().toString(),
                        "status", 401,
                        "error", "Unauthorized",
                        "message", "Authentication required",
                        "path", request.getRequestURI()
                    ));
                })
                .accessDeniedHandler((request, response, e) -> {
                    response.setStatus(403);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    objectMapper.writeValue(response.getWriter(), Map.of(
                        "timestamp", Instant.now().toString(),
                        "status", 403,
                        "error", "Forbidden",
                        "message", "Access denied",
                        "path", request.getRequestURI()
                    ));
                })
            );
        return http.build();
    }
}
