package me.ifelseif.starter.restsecruity;

import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(ClientSecurityProperties.class)
public class ClientJwtTokenGenerator extends AbstractJwtTokenGenerator {

    private SecurityProperties securityProperties;

    public ClientJwtTokenGenerator(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public String getJwtToken() {
        return securityProperties.getClientJwtToken();
    }

    @Override
    public long getJwtTokenExpire() {
        return securityProperties.getClientJwtTokenExpire();
    }
}
