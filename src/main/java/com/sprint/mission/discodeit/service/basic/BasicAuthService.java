package com.sprint.mission.discodeit.service.basic;


import com.sprint.mission.discodeit.dto.request.RoleUpdateRequest;
import com.sprint.mission.discodeit.dto.response.JwtDto;
import com.sprint.mission.discodeit.dto.response.UserResponseDto;
import com.sprint.mission.discodeit.entity.User;
import com.sprint.mission.discodeit.exception.DiscodeitException;
import com.sprint.mission.discodeit.exception.ErrorCode;
import com.sprint.mission.discodeit.exception.user.UserNotFoundException;
import com.sprint.mission.discodeit.mapper.UserMapper;
import com.sprint.mission.discodeit.repository.UserRepository;
import com.sprint.mission.discodeit.security.jwt.JwtTokenProvider;
import com.sprint.mission.discodeit.service.AuthService;
import com.sprint.mission.discodeit.service.UserService;
import io.jsonwebtoken.Claims;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class BasicAuthService implements AuthService {

  private final UserService userService;
  private final UserRepository userRepository;
  private final UserMapper userMapper;
  private final JwtTokenProvider jwtTokenProvider;

  @Override
  @Transactional
  @PreAuthorize("hasRole('ADMIN')")
  public UserResponseDto updateUserRole(RoleUpdateRequest request) {

    User user = userRepository.findById(request.userId())
        .orElseThrow(() -> new UserNotFoundException(request.userId()));

    user.updateRole(request.newRole());

    User saved = userRepository.save(user);
    return userMapper.toDto(saved);
  }

  @Override
  @Transactional(readOnly = true)
  public UserResponseDto validateRefreshToken(String refreshToken) {
    if (refreshToken == null || !jwtTokenProvider.isRefreshToken(refreshToken)) {
      throw new DiscodeitException(ErrorCode.INVALID_TOKEN);
    }

    Claims claims = jwtTokenProvider.validateToken(refreshToken);

    String userIdString = claims.getSubject();
    UUID userId = UUID.fromString(userIdString);

    UserResponseDto userDto = userService.find(userId);

    return userDto;
  }
}
