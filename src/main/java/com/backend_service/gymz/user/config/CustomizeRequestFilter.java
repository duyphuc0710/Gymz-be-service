// package com.backend_service.gymz.user.config;

// import java.io.IOException;

// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.backend_service.gymz.user.common.enums.token.TokenType;
// import com.backend_service.gymz.user.service.CustomizeUserDetailsService;
// import com.backend_service.gymz.user.service.JwtService;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import lombok.RequiredArgsConstructor;
// import lombok.extern.slf4j.Slf4j;

// @Component
// @RequiredArgsConstructor
// @Slf4j(topic = "CUSTOMIZE-REQUEST-FILTER")
// public class CustomizeRequestFilter extends OncePerRequestFilter{

//     private final JwtService jwtService;
//     private final CustomizeUserDetailsService customizeUserDetailsService;

//     @Override
//     protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//             throws ServletException, IOException {
//        final String authHeader = request.getHeader("Authorization");
//         final String jwt;
//         final String username;

//         // Check if Authorization header exists and starts with "Bearer "
//         if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//             log.debug("No JWT token found in request headers");
//             filterChain.doFilter(request, response);
//             return;
//         }

//         // Extract JWT token from Authorization header
//         jwt = authHeader.substring(7);
//         log.debug("JWT token extracted from request");

//         try {
//             username = jwtService.extractUsername(jwt, TokenType.ACCESS_TOKEN);
            
//             if (username != null) {
//                 log.debug("Username extracted from JWT: {}", username);
//             } else {
//                 log.debug("No username found in JWT token");
//                 filterChain.doFilter(request, response);
//                 return;
//             }

//             if (SecurityContextHolder.getContext().getAuthentication() == null) {
                
//                 UserDetails userDetails = customizeUserDetailsService.loadUserByUsername(username);
//                 log.debug("User details loaded for username: {}", username);

//                 if (jwtService.validateToken(jwt, userDetails, TokenType.ACCESS_TOKEN)) {
//                     log.debug("JWT token is valid for user: {}", username);
                    
//                     UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//                     authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                     SecurityContextHolder.getContext().setAuthentication(authToken);
//                     log.debug("Authentication set in SecurityContext for user: {}", username);
//                 } else {
//                     log.warn("Invalid JWT token for user: {}", username);
//                 }
//             }
//         } catch (Exception e) {
//             log.error("Cannot set user authentication: {}", e.getMessage());
//         }

//         filterChain.doFilter(request, response);
//     }
    
// }
