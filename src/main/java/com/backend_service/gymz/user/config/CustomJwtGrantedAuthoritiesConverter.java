package com.backend_service.gymz.user.config;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> { 
    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String CLIENT_ID = "nsa2-gateway"; // Your Keycloak client ID
    private static final String ROLES = "roles";

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public Collection<GrantedAuthority> convert(@NonNull Jwt source) {
        Collection<GrantedAuthority> authorities = defaultGrantedAuthoritiesConverter.convert(source);
        log.info("authorities : {}", authorities);

        var roles = source.getClaimAsStringList("roles");
        log.info("roles: {}", roles);


        Map<String, Object> resourceAccess = source.getClaimAsMap(RESOURCE_ACCESS);

        
        if (resourceAccess != null && resourceAccess.containsKey(CLIENT_ID)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(CLIENT_ID);
            if (clientAccess.containsKey(ROLES)) {
                @SuppressWarnings("unchecked")
                List<String> clientRoles = (List<String>) clientAccess.get(ROLES);
                authorities = Stream.concat(
                        authorities.stream(),
                        clientRoles.stream().map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role).map(SimpleGrantedAuthority::new)
                ).collect(Collectors.toList());
            }
        }

        log.info("authorities : {}", authorities);

        return authorities;
    }

}        
    

