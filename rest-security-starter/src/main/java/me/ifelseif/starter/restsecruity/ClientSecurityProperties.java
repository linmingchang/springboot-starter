package me.ifelseif.starter.restsecruity;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "lmc.security.client")
public class ClientSecurityProperties {

    private String jwtToken;

    private long jwtTokenExpire;
}
