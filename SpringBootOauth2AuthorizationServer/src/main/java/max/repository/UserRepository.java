package max.repository;

import max.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByeMailAddress(String eMailAddress);
}
