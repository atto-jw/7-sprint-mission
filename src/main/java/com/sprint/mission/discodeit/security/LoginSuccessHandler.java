package com.sprint.mission.discodeit.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sprint.mission.discodeit.dto.response.JwtDto;
import com.sprint.mission.discodeit.dto.response.UserResponseDto;
import com.sprint.mission.discodeit.security.jwt.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

  private final ObjectMapper objectMapper;
  private final JwtTokenProvider jwtTokenProvider;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    DiscodeitUserDetails userDetails = (DiscodeitUserDetails) authentication.getPrincipal();
    UserResponseDto userDto = userDetails.getUserDto();

    String accessToken = jwtTokenProvider.generateAccessToken(userDto);
    String refreshToken = jwtTokenProvider.generateRefreshToken(userDto);

    Cookie refreshCookie = new Cookie("REFRESH_TOKEN", refreshToken);
    refreshCookie.setHttpOnly(true);
    refreshCookie.setSecure(false);
    refreshCookie.setPath("/");
    refreshCookie.setMaxAge(14 * 24 * 60 * 60);
    response.addCookie(refreshCookie);

    JwtDto jwtDto = new JwtDto(userDto, accessToken);

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");

    String json = objectMapper.writeValueAsString(jwtDto);
    response.getWriter().write(json);
  }
}
