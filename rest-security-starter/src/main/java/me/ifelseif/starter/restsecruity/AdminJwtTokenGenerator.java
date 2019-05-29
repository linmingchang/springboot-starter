package me.ifelseif.starter.restsecruity;

import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties({SecurityProperties.class})
public class AdminJwtTokenGenerator extends AbstractJwtTokenGenerator {

    private SecurityProperties securityProperties;

    public AdminJwtTokenGenerator(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public String getJwtToken() {
        return securityProperties.getAdminJwtToken();
    }

    @Override
    public long getJwtTokenExpire() {
        return securityProperties.getAdminJwtTokenExpire();
    }
}
