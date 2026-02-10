package com.sprint.mission.discodeit.security.jwt;

import com.sprint.mission.discodeit.entity.User;
import com.sprint.mission.discodeit.exception.DiscodeitException;
import com.sprint.mission.discodeit.exception.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtTokenProvider {

  private final JwtProperties jwtProperties;

  private SecretKey getSecretKey() {
    byte[] keyBytes = jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String generateAccessToken(User user) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtProperties.getAccessTokenExpiration());

    return Jwts.builder()
        .header()
        .type("JWT")
        .and()
        .issuer(jwtProperties.getIssuer())
        .subject(user.getId().toString())
        .issuedAt(now)
        .expiration(expiryDate)
        .claim("email", user.getEmail())
        .claim("username", user.getUsername())
        .claim("role", user.getRole().name())
        .claim("token_type", "access")
        .signWith(getSecretKey())
        .compact();
  }

  public String generateRefreshToken(User user) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtProperties.getRefreshTokenExpiration());

    return Jwts.builder()
        .header()
        .type("JWT")
        .and()
        .issuer(jwtProperties.getIssuer())
        .subject(user.getId().toString())
        .issuedAt(now)
        .expiration(expiryDate)
        .claim("token_type", "refresh")
        .signWith(getSecretKey())
        .compact();
  }

  public Claims validateToken(String token) {
    try {
      return Jwts.parser()
          .verifyWith(getSecretKey())
          .build()
          .parseSignedClaims(token)
          .getPayload();
    } catch (ExpiredJwtException e) {
      log.warn("만료된 JWT 토큰: {}", e.getMessage());
      throw new DiscodeitException(ErrorCode.EXPIRED_TOKEN);

    } catch (UnsupportedJwtException e) {
      log.warn("지원하지 않는 JWT 토큰: {}", e.getMessage());
      throw new DiscodeitException(ErrorCode.UNSUPPORTED_TOKEN);

    } catch (MalformedJwtException | SecurityException | IllegalArgumentException e) {
      log.warn("유효하지 않는 JWT 토큰: {}", e.getMessage());
      throw new DiscodeitException(ErrorCode.INVALID_TOKEN);
    }
  }

  public boolean isTokenValid(String token) {
    try {
      validateToken(token);
      return true;
    } catch (DiscodeitException e) {
      return false;
    }
  }

  public String getUserId(String token) {
    Claims claims = validateToken(token);
    return claims.getSubject();
  }

  public String getUsername(String token) {
    Claims claims = validateToken(token);
    return claims.get("username", String.class);
  }

  public String getEmail(String token) {
    Claims claims = validateToken(token);
    return claims.get("email", String.class);
  }

  public String getRole(String token) {
    Claims claims = validateToken(token);
    return claims.get("role", String.class);
  }
}
