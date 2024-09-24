package max.config;

import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;


@HttpExchange("http://localhost:8130/home")
public interface WelcomeClient {

	@GetExchange("/")
	String getWelcome();


}
