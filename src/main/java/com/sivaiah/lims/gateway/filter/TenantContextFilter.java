package com.sivaiah.lims.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Extracts Tenant / Branch / Department context from the incoming request
 * (query params, path variables, or headers) and normalises them into
 * canonical X-Tenant-Id / X-Branch-Id / X-Department-Id headers so every
 * downstream service receives a consistent, predictable contract.
 *
 * The JWT filter may also set these headers from token claims; values
 * present in the JWT take precedence via the ordering of filters.
 *
 * Accepted sources (in priority order):
 *  1. JWT claims  (set by JwtAuthenticationFilter which runs after this one)
 *  2. X-Tenant-Id request header
 *  3. ?tenantId= query parameter
 */
@Slf4j
@Component
public class TenantContextFilter implements GlobalFilter, Ordered {

    @Override
    public int getOrder() {
        // Run after CommonHeadersFilter but before RateLimitFilter
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerWebExchange mutated = exchange.mutate()
                .request(r -> r.headers(headers -> {
                    // Tenant
                    String tenantId = resolveFirst(exchange, "X-Tenant-Id", "tenantId");
                    if (tenantId != null) headers.set("X-Tenant-Id", tenantId);

                    // Branch
                    String branchId = resolveFirst(exchange, "X-Branch-Id", "branchId");
                    if (branchId != null) headers.set("X-Branch-Id", branchId);

                    // Department
                    String deptId = resolveFirst(exchange, "X-Department-Id", "departmentId");
                    if (deptId != null) headers.set("X-Department-Id", deptId);
                }))
                .build();

        logContext(mutated);
        return chain.filter(mutated);
    }

    /** Return header value first, then fall back to query param. */
    private String resolveFirst(ServerWebExchange exchange, String headerName, String queryParam) {
        String fromHeader = exchange.getRequest().getHeaders().getFirst(headerName);
        if (fromHeader != null && !fromHeader.isBlank()) return fromHeader;

        String fromQuery = exchange.getRequest().getQueryParams().getFirst(queryParam);
        if (fromQuery != null && !fromQuery.isBlank()) return fromQuery;

        return null;
    }

    private void logContext(ServerWebExchange exchange) {
        String tenant = exchange.getRequest().getHeaders().getFirst("X-Tenant-Id");
        String branch = exchange.getRequest().getHeaders().getFirst("X-Branch-Id");
        String dept = exchange.getRequest().getHeaders().getFirst("X-Department-Id");
        if (tenant != null || branch != null || dept != null) {
            log.debug("TenantContext tenant={} branch={} department={}", tenant, branch, dept);
        }
    }
}