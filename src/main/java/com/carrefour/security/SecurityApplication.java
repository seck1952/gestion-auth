package com.carrefour.security;

import com.carrefour.security.entity.auth.RegisterRequest;
import com.carrefour.security.services.AuthenticationService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import static com.carrefour.security.entity.enums.Role.ADMIN;
import static com.carrefour.security.entity.enums.Role.MANAGER;

@SpringBootApplication
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = new RegisterRequest();
			admin.setFirstname("Admin");
			admin.setLastname("Admin");
			admin.setEmail("admin@mail.com");
			admin.setPassword("password");
			admin.setRole(ADMIN);

			System.out.println("Admin token: " + service.register(admin).getAccessToken());

			var manager = new  RegisterRequest();
			manager.setFirstname("Admin");
			manager.setLastname("Admin");
			manager.setEmail("manager@mail.com");
			manager.setPassword("password");
			manager.setRole(MANAGER);

			System.out.println("Manager token: " + service.register(manager).getAccessToken());

		};
	}

}
