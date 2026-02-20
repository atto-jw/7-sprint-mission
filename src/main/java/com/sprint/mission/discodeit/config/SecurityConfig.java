package com.sprint.mission.discodeit.config;

import com.sprint.mission.discodeit.security.CustomAccessDeniedHandler;
import com.sprint.mission.discodeit.security.CustomAuthenticationEntryPoint;
import com.sprint.mission.discodeit.security.LoginFailureHandler;
import com.sprint.mission.discodeit.security.LoginSuccessHandler;
import com.sprint.mission.discodeit.security.SpaCsrfTokenRequestHandler;
import com.sprint.mission.discodeit.security.jwt.JwtAuthenticationFilter;
import com.sprint.mission.discodeit.security.jwt.JwtLogoutHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final LoginSuccessHandler loginSuccessHandler;
  private final LoginFailureHandler loginFailureHandler;
  private final CustomAuthenticationEntryPoint authenticationEntryPoint;
  private final CustomAccessDeniedHandler accessDeniedHandler;
  private final JwtAuthenticationFilter JwtAuthenticationFilter;
  private final JwtLogoutHandler jwtLogoutHandler;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .addFilterBefore(JwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .csrf(AbstractHttpConfigurer::disable)

        .formLogin(login ->
            login.loginProcessingUrl("/api/auth/login")
                .successHandler(loginSuccessHandler)
                .failureHandler(loginFailureHandler)
        )
        .logout(logout ->
            logout.logoutUrl("/api/auth/logout")
                .addLogoutHandler(jwtLogoutHandler)
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(
                    HttpStatus.NO_CONTENT))
        )
        .exceptionHandling(ex ->
            ex.authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)

        )
        .authorizeHttpRequests(auth ->
            auth.requestMatchers("/api/users").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api-docs.html", "/swagger-ui/**", "/swagger-ui.html",
                    "/v3/api-docs/**").permitAll()
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/", "/*.html", "/*.css", "/*.js", "/assets/**").permitAll()
                .anyRequest().authenticated()
        );

    return http.build();
  }

}
