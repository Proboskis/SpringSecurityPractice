package com.proboskis.SpringSecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static com.proboskis.SpringSecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable().authorizeHttpRequests()
                .requestMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .requestMatchers("/api/**").hasRole(STUDENT.name())
                .requestMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
                .requestMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
                .requestMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
                .requestMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest().authenticated().and().httpBasic();
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() throws Exception {
        UserDetails annaSmithUser = User.builder().username("anna smith")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name()).build(); // ROLE_STUDENT

        UserDetails LindaUser = User.builder().username("Linda")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name()).build();

        UserDetails tomUser = User.builder().username("tom")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMINTRAINEE.name()).build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                LindaUser,
                tomUser
        );
    }
}
