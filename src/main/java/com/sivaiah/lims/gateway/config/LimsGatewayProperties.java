package com.sivaiah.lims.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "gateway")
public class LimsGatewayProperties {

    private Jwt jwt = new Jwt();
    private RateLimit rateLimit = new RateLimit();

    @Data
    public static class Jwt {
        private String secret;
        private List<String> publicPaths = List.of();
    }

    @Data
    public static class RateLimit {
        private long capacity = 100;
        private long refillTokens = 100;
        private long refillDurationSeconds = 60;
    }
}
