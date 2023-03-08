package ru.kata.spring.boot_security.bootstrap.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.kata.spring.boot_security.bootstrap.model.User;


@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("select u from User u " +
            "join fetch u.roles " +
            "where u.email=:username ")
    User findByUsername(@Param("username") String username);
}
