package com.example.jwtdemo.service;

import com.example.jwtdemo.domain.AppUser;
import com.example.jwtdemo.domain.Role;

import java.util.List;

public interface AppUserService {
    AppUser saveAppUser(AppUser appUser);
    Role saveRole(Role role);
    void addRoleToAppUser(String username,String roleName);
    AppUser getAppUser(String username);
    List<AppUser> getAppUser();
}
