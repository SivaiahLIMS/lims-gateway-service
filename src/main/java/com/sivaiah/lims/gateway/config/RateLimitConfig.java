package com.sivaiah.lims.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

/**
 * Key resolvers used by Spring Cloud Gateway's built-in RequestRateLimiter filter
 * (defined in application.yml route filters).
 */
@Configuration
public class RateLimitConfig {

    /** Resolve rate-limit bucket by client IP address. */
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return Mono.just(forwarded.split(",")[0].trim());
            }
            var remote = exchange.getRequest().getRemoteAddress();
            return Mono.just(remote != null ? remote.getAddress().getHostAddress() : "unknown");
        };
    }

    /** Resolve rate-limit bucket by authenticated user (falls back to IP). */
    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> {
            String userId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
            if (userId != null && !userId.isBlank()) {
                return Mono.just("user:" + userId);
            }
            return ipKeyResolver().resolve(exchange);
        };
    }
}