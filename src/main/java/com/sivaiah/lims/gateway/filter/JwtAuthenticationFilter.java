package com.sivaiah.lims.gateway.filter;

import com.sivaiah.lims.gateway.config.LimsGatewayProperties;
import com.sivaiah.lims.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * Validates Bearer JWT on every request except configured public paths.
 * On success, enriches downstream headers with extracted claims.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final String BEARER_PREFIX = "Bearer ";
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final JwtUtil jwtUtil;
    private final LimsGatewayProperties properties;

    @Override
    public int getOrder() {
        // Run after CORS filter, before routing
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "Missing or malformed Authorization header");
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        Optional<Claims> claimsOpt = jwtUtil.validateAndExtract(token);

        if (claimsOpt.isEmpty()) {
            return unauthorized(exchange, "Invalid or expired JWT");
        }

        Claims claims = claimsOpt.get();
        log.debug("JWT valid for subject={} path={}", claims.getSubject(), path);

        // Forward enriched headers to downstream services
        ServerWebExchange enriched = exchange.mutate()
                .request(r -> r.headers(h -> {
                    h.set("X-User-Id", safeGet(jwtUtil.extractSubject(claims)));
                    h.set("X-Tenant-Id", safeGet(jwtUtil.extractTenantId(claims)));
                    h.set("X-Branch-Id", safeGet(jwtUtil.extractBranchId(claims)));
                    h.set("X-Department-Id", safeGet(jwtUtil.extractDepartmentId(claims)));
                    h.set("X-User-Roles", safeGet(jwtUtil.extractRoles(claims)));
                    // Remove the raw Authorization header if you don't want it forwarded
                    // h.remove(HttpHeaders.AUTHORIZATION);
                }))
                .build();

        return chain.filter(enriched);
    }

    private boolean isPublicPath(String path) {
        return properties.getJwt().getPublicPaths().stream()
                .anyMatch(p -> pathMatcher.match(p, path));
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        log.warn("Unauthorized request to {}: {}", exchange.getRequest().getPath(), message);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = ("{\"error\":\"Unauthorized\",\"message\":\"" + message + "\"}").getBytes();
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
    }

    private String safeGet(String value) {
        return value != null ? value : "";
    }
}