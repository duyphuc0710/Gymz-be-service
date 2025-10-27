package com.backend_service.gymz.user.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.backend_service.gymz.user.service.CustomizeUserDetailsService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Configuration
@RequiredArgsConstructor
@Slf4j
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    // Public endpoints that don't require authentication
    private static final String[] PUBLIC_ENDPOINTS = {
        "/", "/login", "/dashboard", "/api/auth/**", 
        "/swagger-ui/**", "/v3/api-docs/**", "/api/test/public",
        "/css/**", "/js/**", "/images/**"
    };

    private final String jwkSetUri = "http://localhost:9000/realms/nsa2-realm/protocol/openid-connect/certs";

    private final CustomizeUserDetailsService customUserDetailsService;
    private final CustomizeRequestFilter customizeRequestFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    /**
     * SECURITY FILTER CHAIN 1 - HIGHEST PRIORITY
     * Purpose: OAuth2 Resource Server (API endpoints with Keycloak JWT)
     * Handles: API requests with Bearer tokens (RS256 from Keycloak)
     * Pattern: /api/** (excluding /api/auth/**)
     * Session: Stateless
     * Authentication: JWT validation via Keycloak JWK Set
     */
    @Bean
    @Order(1)
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring Resource Server Filter Chain (Order 1)");
        
        http
            .securityMatcher("/api/**")  // Match all API endpoints
            .csrf(csrf -> csrf.disable())  // Disable CSRF for stateless APIs
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**", "/api/test/public").permitAll()  // Allow auth endpoints
                .anyRequest().authenticated()  // All other API requests require authentication
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // No session creation
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(keycloakJwtAuthenticationConverter())
                    .jwkSetUri(jwkSetUri)
                )
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
            );

        return http.build();
    }

    /**
     * SECURITY FILTER CHAIN 2 - MEDIUM PRIORITY
     * Purpose: OAuth2 Client (OAuth2 Login Flow)
     * Handles: OAuth2/OIDC login redirects and authorization code flow
     * Pattern: /oauth2/**, /login/oauth2/**
     * Session: Stateful (required for OAuth2 authorization flow)
     * Authentication: OAuth2 login with Keycloak
     */
    @Bean
    @Order(2)
    public SecurityFilterChain oauth2ClientFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring OAuth2 Client Filter Chain (Order 2)");
        
        http
            .securityMatcher("/oauth2/**", "/login/oauth2/**", "/authorized/**")
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()  // OAuth2 endpoints are public (Spring Security handles auth)
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)  // Session needed for OAuth2 flow
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/dashboard", true)
                // You can add custom success handler here if needed
                // .successHandler(customOAuth2SuccessHandler())
            )
            .oauth2Client(Customizer.withDefaults());

        return http.build();
    }

    /**
     * SECURITY FILTER CHAIN 3 - LOWEST PRIORITY (CATCH-ALL)
     * Purpose: Traditional username/password authentication from database
     * Handles: All remaining requests with custom JWT (HS256)
     * Pattern: /** (catch-all for non-matched requests)
     * Session: Stateless
     * Authentication: UserDetailsService + Custom JWT Filter
     */
    @Bean
    @Order(3)
    public SecurityFilterChain databaseAuthFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring Database Authentication Filter Chain (Order 3)");
        
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(databaseAuthenticationProvider())
            .addFilterBefore(customizeRequestFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
            );

        return http.build();
    }


    // ============================================
    // AUTHENTICATION CONVERTERS & PROVIDERS
    // ============================================

    /**
     * JWT Authentication Converter for Keycloak tokens (RS256)
     * Extracts authorities from Keycloak JWT claims
     */
    @Bean
    public JwtAuthenticationConverter keycloakJwtAuthenticationConverter() {
        log.debug("Creating Keycloak JWT Authentication Converter");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtGrantedAuthoritiesConverter());
        return converter;
    }

    /**
     * Database Authentication Provider for username/password authentication
     * Used by custom JWT filter for internal system authentication
     */
    @Bean
    @SuppressWarnings("deprecation")
    public AuthenticationProvider databaseAuthenticationProvider() {
        log.debug("Creating Database Authentication Provider");
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(passwordEncoder());
        provider.setUserDetailsService(customUserDetailsService);
        return provider;
    }

    /**
     * Authentication Manager - required for manual authentication
     * Used in login endpoint to authenticate username/password
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Password Encoder - BCrypt for secure password hashing
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ============================================
    // CORS CONFIGURATION
    // ============================================

    /**
     * CORS Configuration for all security filter chains
     * Allows requests from Keycloak and Gateway
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        log.debug("Configuring CORS");
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of(
                "http://localhost:9000",      // Keycloak local
                "http://auth.nsa2.com:9000",  // Keycloak
                "http://gateway.nsa2.com:8080", // Spring Cloud Gateway
                "http://localhost:3000"       // Frontend (if needed)
        ));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setMaxAge(3600L); // Cache preflight response for 1 hour

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

}