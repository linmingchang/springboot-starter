package me.ifelseif.starter.restsecruity;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public abstract class AbstractJwtTokenGenerator implements JwtTokenGenerator {

    @Override
    public String generateToken(JwtUser jwtUser) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", jwtUser.getUsername());
        claims.put("id", jwtUser.getId());
        LocalDateTime update = LocalDateTime.now();
        LocalDateTime expire = update.plusSeconds(getJwtTokenExpire());
        Instant instant = expire.atZone(ZoneId.systemDefault()).toInstant();
        Date date = Date.from(instant);
        jwtUser.setExpireTime(date.getTime() / 1000);
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(date)
                .signWith(SignatureAlgorithm.HS256, getJwtToken())
                .compact();
    }

    @Override
    public Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .setSigningKey(getJwtToken())
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    @Override
    public JwtUser getJwtUserFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        if (claims != null) {
            JwtUser jwtUser = new JwtUser();
            jwtUser.setId((int) claims.get("id"));
            jwtUser.setUsername((String) claims.get("username"));
            jwtUser.setExpireTime(claims.getExpiration().getTime() / 1000);
            return jwtUser;
        }
        return null;
    }

    @Override
    public String getUsernameFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        if (claims != null) {
            return (String) claims.get("username");
        }
        return null;
    }

    @Override
    public Boolean isTokenExpired(String token) {
        Claims claims = getClaimsFromToken(token);
        if (Objects.isNull(claims)) {
            return true;
        }
        final Date expiration = claims.getExpiration();
        return expiration.before(new Date());
    }

    public abstract String getJwtToken();

    public abstract long getJwtTokenExpire();
}
