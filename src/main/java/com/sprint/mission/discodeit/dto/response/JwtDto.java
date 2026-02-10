package com.sprint.mission.discodeit.dto.response;

public record JwtDto(

    UserResponseDto userDto,
    String accessToken
) {

}
