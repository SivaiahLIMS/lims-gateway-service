package com.sivaiah.lims.gateway.util;

import com.sivaiah.lims.gateway.config.LimsGatewayProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final LimsGatewayProperties properties;

    private SecretKey signingKey() {
        return Keys.hmacShaKeyFor(
                properties.getJwt().getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Parse and validate the JWT. Returns the claims on success, empty on any failure.
     */
    public Optional<Claims> validateAndExtract(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return Optional.of(claims);
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("JWT validation failed: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    public String extractSubject(Claims claims) {
        return claims.getSubject();
    }

    public String extractTenantId(Claims claims) {
        return claims.get("tenantId", String.class);
    }

    public String extractBranchId(Claims claims) {
        return claims.get("branchId", String.class);
    }

    public String extractDepartmentId(Claims claims) {
        return claims.get("departmentId", String.class);
    }

    public String extractRoles(Claims claims) {
        Object roles = claims.get("roles");
        return roles != null ? roles.toString() : "";
    }
}