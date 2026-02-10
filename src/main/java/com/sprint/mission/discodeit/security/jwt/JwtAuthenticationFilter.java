package com.sprint.mission.discodeit.security.jwt;

import com.sprint.mission.discodeit.dto.response.UserResponseDto;
import com.sprint.mission.discodeit.enum_.Role;
import com.sprint.mission.discodeit.security.DiscodeitUserDetails;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtTokenProvider jwtTokenProvider;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    try {
      String jwt = extractJwtFromRequest(request);

      if (jwt != null && jwtTokenProvider.isTokenValid(jwt)) {
        authenticateUser(jwt, request);
      }
    } catch (Exception e) {
      log.error("JWT 인증 실패: {}", e.getMessage());
    }
    filterChain.doFilter(request, response);
  }

  private void authenticateUser(String jwt, HttpServletRequest request) {
    Claims claims = jwtTokenProvider.validateToken(jwt);

    UUID userId = UUID.fromString(claims.getSubject());
    String email = claims.get("email", String.class);
    String username = claims.get("username", String.class);
    Role role = Role.valueOf(claims.get("role", String.class));

    UserResponseDto userDto = new UserResponseDto(
        userId, username, email, null, null, role);

    DiscodeitUserDetails userDetails = new DiscodeitUserDetails(userDto, null);

    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
        userDetails, null, userDetails.getAuthorities());

    authentication.setDetails(
        new WebAuthenticationDetailsSource().buildDetails(request));
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  private String extractJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");

    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7);
    }
    return null;
  }
}
