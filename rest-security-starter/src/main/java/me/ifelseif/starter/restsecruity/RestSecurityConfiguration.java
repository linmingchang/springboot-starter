package me.ifelseif.starter.restsecruity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties({SecurityProperties.class})
public class RestSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    SecurityProperties securityProperties;

    @Override
    public void configure(WebSecurity webSecurity) throws Exception {
        webSecurity.ignoring().antMatchers("/health");
        webSecurity.ignoring().antMatchers("/v2/api-docs/**");
        webSecurity.ignoring().antMatchers("/swagger.json");
        webSecurity.ignoring().antMatchers("/swagger-ui.html");
        webSecurity.ignoring().antMatchers("/swagger-resources/**");
        webSecurity.ignoring().antMatchers("/webjars/**");
        webSecurity.ignoring().antMatchers("/autoload-cache/**");
    }

    @Bean
    public AdminJwtTokenGenerator adminJwtTokenGenerator() {
        return new AdminJwtTokenGenerator(securityProperties);
    }

    @Bean
    public ClientJwtTokenGenerator clientJwtTokenGenerator() {
        return new ClientJwtTokenGenerator(securityProperties);
    }

    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationTokenFilter();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // 由于使用的是JWT，我们这里不需要csrf
                .csrf().disable()

                // 基于token，所以不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

                .authorizeRequests()
                // 允许对于网站静态资源的无授权访问
                .antMatchers(
                        HttpMethod.GET,
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                ).permitAll()
                // 对于获取token的rest api要允许匿名访问
                //todo 可配置
                .antMatchers("/app/aex/**", "/app/auth/**", "/app/coin_put_in/**", "/admin/auth/**", "/autoload-cache/**").permitAll()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();

        httpSecurity.exceptionHandling().authenticationEntryPoint(new RestAuthenticationEntryPoint());

        httpSecurity
                .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

        // 禁用缓存
        httpSecurity.headers().cacheControl();
    }
}
