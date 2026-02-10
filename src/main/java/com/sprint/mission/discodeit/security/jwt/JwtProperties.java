package com.sprint.mission.discodeit.security.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ConfigurationProperties(prefix = "discodeit.jwt")
public class JwtProperties {

  private String secretKey;

  private Long accessTokenExpiration;

  private Long refreshTokenExpiration;

  private String issuer;
}
