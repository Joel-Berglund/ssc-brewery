package guru.sfg.brewery.repositories.security;

import java.sql.Timestamp;
import java.util.List;

import guru.sfg.brewery.domain.security.LoginFailure;
import guru.sfg.brewery.domain.security.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface LoginFailureRepository extends JpaRepository<LoginFailure, Integer> {

    List<LoginFailure> findAllByUserAndCreatedDateIsAfter(User user, Timestamp timestamp);
}
