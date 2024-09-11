package max.service;

import max.dto.UserDto;
import max.entity.User;

public interface UserService {

    User registerUser(UserDto userDto);
    User findUserByEmail(String email);
}
