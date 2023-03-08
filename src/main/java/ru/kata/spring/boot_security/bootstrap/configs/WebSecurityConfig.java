package ru.kata.spring.boot_security.bootstrap.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final SuccessUserHandler successUserHandler;
    private final UserDetailsService userDetailsServiceService;


    public WebSecurityConfig(SuccessUserHandler successUserHandler, UserDetailsService userDetailsServiceService) {
        this.successUserHandler = successUserHandler;
        this.userDetailsServiceService = userDetailsServiceService;

    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/admin/**").hasAnyRole("ADMIN")

                .anyRequest().authenticated()
                .and()
                .formLogin()
                .successHandler(successUserHandler)
                .and()
                .logout()
                .permitAll();
    }

    @Bean
    public static PasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(){

        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(encoder());
        authenticationProvider.setUserDetailsService(userDetailsServiceService);

        return authenticationProvider;
    }
}