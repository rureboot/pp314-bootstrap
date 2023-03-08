package ru.kata.spring.boot_security.bootstrap.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.kata.spring.boot_security.bootstrap.model.User;
import ru.kata.spring.boot_security.bootstrap.services.UserService;

import java.security.Principal;

@Controller
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }



    @GetMapping(value = {"/", ""})
    public String myController(Principal principal, Model model) {

        String currentUserName = principal.getName();
        User currentUser = userService.findByEmail(currentUserName);


        model.addAttribute("currentUser", currentUser);

        return "user";
    }


}
