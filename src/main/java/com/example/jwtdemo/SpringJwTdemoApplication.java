package com.example.jwtdemo;

import com.example.jwtdemo.domain.AppUser;
import com.example.jwtdemo.domain.Role;
import com.example.jwtdemo.service.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringJwTdemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwTdemoApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run (AppUserService appUserService){
		return args -> {
			appUserService.saveRole(new Role(null,"ROLE_USER"));
			appUserService.saveRole(new Role(null,"ROLE_MANAGER"));
			appUserService.saveRole(new Role(null,"ROLE_ADMIN"));
			appUserService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));

			appUserService.saveAppUser(new AppUser(null,"John Travolta","john","123456",new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null,"Will Smith","will","123456",new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null,"Jim Carry","jim","123456",new ArrayList<>()));
			appUserService.saveAppUser(new AppUser(null,"Anna Klar","anne","123456",new ArrayList<>()));

			appUserService.addRoleToAppUser("john","ROLE_USER");
			appUserService.addRoleToAppUser("john","ROLE_MANAGER");
			appUserService.addRoleToAppUser("will","ROLE_MANAGER");
			appUserService.addRoleToAppUser("jim","ROLE_ADMIN");
			appUserService.addRoleToAppUser("anne", "ROLE_SUPER_ADMIN");
			appUserService.addRoleToAppUser("anne", "ROLE_ADMIN");
			appUserService.addRoleToAppUser("anne", "ROLE_USER");
		};
	}

}
