package ru.rtln.common.security.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticatedUserModel {

    private Long id;

    private List<String> permissions = List.of();

    private String city;

    public void setPermissions(List<String> permissions) {
        this.permissions = (permissions == null) ? List.of() : permissions;
    }
}