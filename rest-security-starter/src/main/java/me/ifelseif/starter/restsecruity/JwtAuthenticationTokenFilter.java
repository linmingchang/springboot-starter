package me.ifelseif.starter.restsecruity;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private AdminJwtTokenGenerator adminJwtTokenGenerator;

    @Autowired
    private ClientJwtTokenGenerator clientJwtTokenGenerator;

    private String tokenHeader = "Authorization";

    private String tokenHead = "Bearer ";

    private AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher("/admin/**");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        JwtTokenGenerator jwtTokenGenerator = getJwtUserFromToken(request);
        String authHeader = request.getHeader(this.tokenHeader);
        if (authHeader != null && authHeader.startsWith(tokenHead)) {
            final String authToken = authHeader.substring(tokenHead.length());

            if (jwtTokenGenerator.isTokenExpired(authToken)) {
                SecurityContextHolder.getContext().setAuthentication(null);
            } else {
                JwtUser jwtUser = jwtTokenGenerator.getJwtUserFromToken(authToken);

                // 未获取到jwtUser信息，说明未登录授权，需要清空历史授权
                if (jwtUser == null) {
                    SecurityContextHolder.getContext().setAuthentication(null);
                } else {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            jwtUser, null, jwtUser.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info("checking authentication " + jwtUser.getUsername());
                }
            }
        }

        filterChain.doFilter(request, httpServletResponse);
    }

    private JwtTokenGenerator getJwtUserFromToken(HttpServletRequest request) {
        if (antPathRequestMatcher.matches(request)) {
            return adminJwtTokenGenerator;
        }
        return clientJwtTokenGenerator;
    }
}
