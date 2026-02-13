package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.persistence.EntityManager;
import javax.servlet.http.Cookie;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SpringSecurityMisconfig {

    // CSRF disabled without justification
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .headers(headers -> headers.frameOptions(frame -> frame.disable()))
            .sessionManagement(session -> session.sessionFixation(fix -> fix.none()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/**").permitAll()
            )
            .build();
    }

    // Insecure CORS: allow all origins with credentials
    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowCredentials(true);
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // Insecure cookie
    public void setSessionCookie(javax.servlet.http.HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("session", token);
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    // Native query injection
    public java.util.List<?> findByName(EntityManager entityManager, String name) {
        return entityManager.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'")
            .getResultList();
    }
}
