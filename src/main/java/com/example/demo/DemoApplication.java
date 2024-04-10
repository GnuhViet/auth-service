package com.example.demo;

import com.example.demo.authentication.dtos.DetailsAppUserDTO;
import com.example.demo.user.constans.UserStatus;
import com.example.demo.user.entities.AppUser;
import com.example.demo.user.entities.Role;
import com.example.demo.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@SpringBootApplication
public class DemoApplication {
	private final PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@Bean
	CommandLineRunner run(UserService userService
	) {
		return args -> {
			// List<DetailsAppUserDTO> user = new ArrayList<>();
			//
			// userService.saveRole(new Role(null, "ROLE_USER"));
			// userService.saveRole(new Role(null, "ROLE_ADMIN"));
			//
			// user.add(userService.saveUser(AppUser.builder()
			// 		.username("string")
			// 		.password(passwordEncoder.encode("string"))
			// 		.build()
			// ));
			//
			// userService.addRoleToUser("string", "ROLE_USER");
			// userService.addRoleToUser("string", "ROLE_ADMIN");
			//
			// user.add(userService.saveUser(AppUser.builder()
			// 		.username("user")
			// 		.password(passwordEncoder.encode("string"))
			// 		.status(UserStatus.Inactive.name())
			// 		.build()
			// ));
			//
			// userService.addRoleToUser("user", "ROLE_USER");


			log.info("Finish test data initial");
		};
	}
}
