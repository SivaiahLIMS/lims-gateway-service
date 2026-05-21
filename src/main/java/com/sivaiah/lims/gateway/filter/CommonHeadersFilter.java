package com.sivaiah.lims.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Adds a unique X-Request-Id to every inbound request (if not already present)
 * and stamps common security/tracing headers on every outbound response.
 */
@Slf4j
@Component
public class CommonHeadersFilter implements GlobalFilter, Ordered {

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String requestId = exchange.getRequest().getHeaders()
                .getFirst("X-Request-Id");

        if (requestId == null || requestId.isBlank()) {
            requestId = UUID.randomUUID().toString();
        }

        final String finalRequestId = requestId;

        ServerWebExchange mutated = exchange.mutate()
                .request(r -> r.headers(h -> h.set("X-Request-Id", finalRequestId)))
                .build();

        mutated.getResponse().getHeaders().set("X-Request-Id", finalRequestId);
        mutated.getResponse().getHeaders().set("X-Content-Type-Options", "nosniff");
        mutated.getResponse().getHeaders().set("X-Frame-Options", "DENY");
        mutated.getResponse().getHeaders().set("X-XSS-Protection", "1; mode=block");
        mutated.getResponse().getHeaders().set("Referrer-Policy", "strict-origin-when-cross-origin");
        mutated.getResponse().getHeaders().set("Cache-Control", "no-store");

        log.debug("Request-Id={} method={} path={}",
                finalRequestId,
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath());

        return chain.filter(mutated);
    }
}