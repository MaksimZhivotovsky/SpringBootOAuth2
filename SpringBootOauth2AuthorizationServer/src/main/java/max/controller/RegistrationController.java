package max.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import max.dto.UserDto;
import max.entity.User;
import max.service.UserService;

@RestController
@Slf4j
@RequiredArgsConstructor
public class RegistrationController {

    private final UserService userService;

    @PostMapping("/register")
    public User registerUser(@RequestBody UserDto userDto, final HttpServletRequest request) {
        return userService.registerUser(userDto);
    }
}
