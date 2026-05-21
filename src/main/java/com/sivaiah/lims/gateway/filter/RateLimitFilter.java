package com.sivaiah.lims.gateway.filter;

import com.sivaiah.lims.gateway.config.LimsGatewayProperties;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.time.Duration;

/**
 * Per-IP rate limiting backed by Caffeine + Bucket4j.
 * Swap the cache for a Redis-backed store in a clustered deployment.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter implements GlobalFilter, Ordered {

    private final LimsGatewayProperties properties;

    private final Cache<String, Bucket> bucketCache = Caffeine.newBuilder()
            .maximumSize(100_000)
            .expireAfterAccess(Duration.ofMinutes(10))
            .build();

    @Override
    public int getOrder() {
        // Run before JWT filter
        return -200;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String key = resolveKey(exchange);
        Bucket bucket = bucketCache.get(key, this::newBucket);

        if (bucket.tryConsume(1)) {
            exchange.getResponse().getHeaders().set("X-Rate-Limit-Remaining",
                    String.valueOf(bucket.getAvailableTokens()));
            return chain.filter(exchange);
        }

        log.warn("Rate limit exceeded for key={}", key);
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set("Retry-After", "60");
        byte[] body = "{\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded\"}".getBytes();
        return exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory().wrap(body)));
    }

    private String resolveKey(ServerWebExchange exchange) {
        // Use X-Forwarded-For if behind a reverse proxy; fall back to remote address
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        return remote != null ? remote.getAddress().getHostAddress() : "unknown";
    }

    private Bucket newBucket(String key) {
        LimsGatewayProperties.RateLimit cfg = properties.getRateLimit();
        Bandwidth limit = Bandwidth.builder()
                .capacity(cfg.getCapacity())
                .refillGreedy(cfg.getRefillTokens(), Duration.ofSeconds(cfg.getRefillDurationSeconds()))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
}