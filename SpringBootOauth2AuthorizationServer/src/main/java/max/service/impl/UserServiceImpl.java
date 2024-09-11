package max.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import max.dto.UserDto;
import org.springframework.stereotype.Service;
import max.entity.User;
import max.repository.UserRepository;
import max.service.UserService;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public User registerUser(UserDto userDto) {
        log.info("registerUser userDto {}", userDto);
        User user = new User();
        user.setEmail(userDto.getEmail());
        user.setFirstName(userDto.getFirstName());
        user.setLastName(userDto.getLastName());
        user.setRole("USER");
//        user.setPassword(passwordEncoder.encode(userModel.getPassword()));
        user.setPassword(userDto.getPassword());

        userRepository.save(user);
        return user;
    }

    @Override
    public User findUserByEmail(String email) {
        log.info("findUserByEmail email {}", email);
        return userRepository.findByEmail(email);
    }
}
