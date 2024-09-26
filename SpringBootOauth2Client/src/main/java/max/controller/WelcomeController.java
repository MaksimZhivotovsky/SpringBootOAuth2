package max.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import max.config.WelcomeClient;

import java.time.LocalDateTime;

@RestController
@RequiredArgsConstructor
public class WelcomeController {
	
	private final WelcomeClient welcomeClient;

	@GetMapping("/")
	public String welcome() {

		String welcome = welcomeClient.getWelcome();
		return  welcome ;
	}

	@GetMapping("/home")
	public String home() {
		LocalDateTime time = LocalDateTime.now();
		return "<h1>" + "Welcome Home! - " + time + "</h1>";
	}
	
}
