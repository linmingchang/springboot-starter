package me.ifelseif.starter.restsecruity;

import io.jsonwebtoken.Claims;

public interface JwtTokenGenerator {
    String generateToken(JwtUser jwtUser);

    Claims getClaimsFromToken(String token);

    JwtUser getJwtUserFromToken(String token);

    String getUsernameFromToken(String token);

    public Boolean isTokenExpired(String token);
}
