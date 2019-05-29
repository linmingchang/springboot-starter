package me.ifelseif.starter.restsecruity;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "lmc.security")
public class SecurityProperties {

    private String adminJwtToken;

    private long adminJwtTokenExpire;

    private String clientJwtToken;

    private long clientJwtTokenExpire;
}
