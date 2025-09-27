package com.backend_service.gymz.user.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

    private static final String[] WHITELIST = {
        "/", "/login", "/dashboard", "/api/auth/**", "/swagger-ui/**", "/v3/api-docs/**", "/api/test/public",
        "/css/**", "/js/**", "/images/**"
    };
    // private final String jwkSetUri = "http://auth.nsa2.com:9000/realms/nsa2-realm/protocol/openid-connect/certs";
    private final String jwkSetUri = "http://localhost:9000/realms/nsa2-realm/protocol/openid-connect/certs";

    private final CustomizeUserDetailsService customUserDetailsService;
    // private final CustomizeRequestFilter customizeRequestFilter;

    // @Bean
    // public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    //     http
    //         .csrf(csrf -> csrf.disable())
    //         .authorizeHttpRequests(auth -> auth
    //             .requestMatchers(WHITELIST).permitAll()
    //             .anyRequest().authenticated())
    //         .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    //         .authenticationProvider(authenticationProvider())
    //         .addFilterBefore(customizeRequestFilter, UsernamePasswordAuthenticationFilter.class);
    //         // .exceptionHandling(ex -> ex.authenticationEntryPoint(jwtAuthenticationEntryPoint));

    //     return http.build();

    // }

    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth ->
                        auth
                            .requestMatchers(WHITELIST).permitAll()
                            .anyRequest().authenticated()
                )
                .oauth2Login(Customizer.withDefaults())  // Enables OAuth2 login with success handler
                .oauth2Client(Customizer.withDefaults()) // Enables OAuth2 client
                .csrf(csrf -> csrf.disable())  // Disable CSRF for APIs
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS
                .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(jwt -> jwt
                        .jwtAuthenticationConverter(nsa2AuthenticationConverter())
                        .jwkSetUri(jwkSetUri)
                    )
                ); // Enable OAuth2 Resource Server with JWT

        return http.build();
    }


    @Bean
    public JwtAuthenticationConverter nsa2AuthenticationConverter() {
        var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new CustomJwtGrantedAuthoritiesConverter());
        return converter;
    }

    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of(
                "http://auth.nsa2.com:9000",  // Keycloak
                "http://gateway.nsa2.com:8080" // Spring Cloud Gateway
        ));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {        

        // return NoOpPasswordEncoder.getInstance();
                
        return new BCryptPasswordEncoder();
    }

}
