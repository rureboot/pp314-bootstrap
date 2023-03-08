package ru.kata.spring.boot_security.bootstrap.services;

import org.hibernate.Hibernate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.bootstrap.model.Role;
import ru.kata.spring.boot_security.bootstrap.model.User;
import ru.kata.spring.boot_security.bootstrap.repositories.RoleRepository;
import ru.kata.spring.boot_security.bootstrap.repositories.UserRepository;

import java.util.*;

@Service
public class UserServiceImp implements UserDetailsService, UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;


    @Autowired

    public UserServiceImp(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        initAdmin();
    }



    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = findByEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException("User " + username + " not found in DB");
        }

        return user;
    }

    @Override
    public User findByEmail(String email) {

        return userRepository.findByUsername(email);
    }

    @Override
    public void save(User user) {

        for (String roleName : user.getListPossibleRoles()) {
            Role role = roleRepository.findByName(roleName);
            user.addRole(role);
        }
        Long userId;
        if ((userId = user.getId()) == null || !user.getPassword().equals("leave old password")) {


            String encryptedPassword = encoder.encode(user.getPassword());
            user.setPassword(encryptedPassword);
        } else {
            Optional<User> oldUserData = userRepository.findById(userId);
            user.setPassword(oldUserData.get().getPassword());
        }

        userRepository.save(user);
    }

    @Override
    public List<User> findAll() {

        return userRepository.findAll();
    }

    @Override
    public void deleteById(Long id) {

        userRepository.deleteById(id);
    }

    @Override
    public List<Role> findAllRoles() {
        return roleRepository.findAll();
    }

    @Override
    public User findById(Long id) {
        return userRepository.findById(id).orElse(null);
    }




    @Transactional
    protected void initAdmin() {
        User userAdmin = userRepository.findByUsername("admin@admin");

        if (userAdmin == null) {

            userAdmin = new User();
            userAdmin.setEmail("admin@admin");
            userAdmin.setPassword(encoder.encode("admin"));

            Role roleAdmin = roleRepository.findByName("ROLE_ADMIN");
            if (roleAdmin == null) {
                roleAdmin = new Role();
                roleAdmin.setName("ROLE_ADMIN");
                roleRepository.save(roleAdmin);
            }
            Role roleUser = roleRepository.findByName("ROLE_USER");
            if (roleUser == null) {
                roleUser = new Role();
                roleUser.setName("ROLE_USER");
                roleRepository.save(roleUser);
            }

            Set<Role> roleSet = new HashSet<>();
            roleSet.add(roleAdmin);
            roleSet.add(roleUser);
            userAdmin.setRoles(roleSet);
            userRepository.save(userAdmin);

        }
    }
}
