package ru.kata.spring.boot_security.bootstrap.services;

import ru.kata.spring.boot_security.bootstrap.model.Role;
import ru.kata.spring.boot_security.bootstrap.model.User;

import java.util.List;

public interface UserService {

    User findByEmail(String email);

    void save(User user);
    List<User> findAll();
    void deleteById(Long id);

    List<Role> findAllRoles();
    User findById(Long id);

}
