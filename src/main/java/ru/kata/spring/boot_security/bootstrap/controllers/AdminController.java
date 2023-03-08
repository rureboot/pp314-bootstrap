package ru.kata.spring.boot_security.bootstrap.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.bootstrap.model.Role;
import ru.kata.spring.boot_security.bootstrap.model.User;
import ru.kata.spring.boot_security.bootstrap.services.UserService;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = {"/", ""})
    public String list(Principal principal, Model model) {
        String currentUserName = principal.getName();
        User currentUser = userService.findByEmail(currentUserName);
        List<User> users = userService.findAll();
        User newUser = new User();
        List<Role> roles = userService.findAllRoles();

        model.addAttribute("currentUser", currentUser);
        model.addAttribute("users", users);
        model.addAttribute("newUser", newUser);
        model.addAttribute("roles",roles);

        return "admin";
    }

    @PostMapping("/save")
    public String saveUser(@ModelAttribute User user) {
        userService.save(user);
        return "redirect:/admin";
    }

    @GetMapping("/delete")
    public String delete(@RequestParam Long id) {
        userService.deleteById(id);
        return "redirect:/admin";
    }
}
