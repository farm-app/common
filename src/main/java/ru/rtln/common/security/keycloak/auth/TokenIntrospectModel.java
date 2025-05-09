package ru.rtln.common.security.keycloak.auth;

import lombok.Data;

import java.util.List;

/**
 * Token introspection model.
 */
@Data
public class TokenIntrospectModel {

    private boolean active;
    private String email;
    private UserInfo attributes;

    public record UserInfo(Long userId, String city, List<String> permissions) {
    }
}
