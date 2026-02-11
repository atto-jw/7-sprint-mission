package com.sprint.mission.discodeit.controller;

import com.sprint.mission.discodeit.controller.docs.AuthControllerDocs;
import com.sprint.mission.discodeit.dto.request.RoleUpdateRequest;
import com.sprint.mission.discodeit.dto.response.JwtDto;
import com.sprint.mission.discodeit.dto.response.UserResponseDto;
import com.sprint.mission.discodeit.security.DiscodeitUserDetails;
import com.sprint.mission.discodeit.security.jwt.JwtTokenProvider;
import com.sprint.mission.discodeit.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController implements AuthControllerDocs {

  private final AuthService authService;
  private final JwtTokenProvider jwtTokenProvider;

  @GetMapping("csrf-token")

  public ResponseEntity<Void> getCsrfToken(CsrfToken csrfToken) {
    String tokenValue = csrfToken.getToken();
    log.debug("CSRF Token: {}", tokenValue);
    return ResponseEntity.ok().build();
  }

  @PostMapping("/refresh")
  public ResponseEntity<JwtDto> refresh(
      @CookieValue(value = "REFRESH_TOKEN", required = false) String refreshToken,
      HttpServletResponse response
  ) {
    UserResponseDto userDto = authService.validateRefreshToken(refreshToken);

    String newAccessToken = jwtTokenProvider.generateAccessToken(userDto);
    String newRefreshToken = jwtTokenProvider.generateRefreshToken(userDto);

    Cookie refreshCookie = new Cookie("REFRESH_TOKEN", newRefreshToken);
    refreshCookie.setHttpOnly(true);
    refreshCookie.setSecure(false);
    refreshCookie.setPath("/");
    refreshCookie.setMaxAge(14 * 24 * 60 * 60);
    response.addCookie(refreshCookie);

    JwtDto jwtDto = new JwtDto(userDto, newAccessToken);
    return ResponseEntity.ok(jwtDto);
  }

  @PutMapping("/role")
  public ResponseEntity<UserResponseDto> updateUserRole(
      @Valid @RequestBody RoleUpdateRequest request) {

    UserResponseDto updateRoleUser = authService.updateUserRole(request);
    return ResponseEntity.ok(updateRoleUser);
  }
}
