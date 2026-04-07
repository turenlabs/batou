package com.example.vulnerable;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtWeakKey {

    private static final String secret_key = "mysecretkey123";

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String pass) {
        if (authenticate(username, pass)) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", username);
            claims.put("role", "user");

            String token = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                    .signWith(SignatureAlgorithm.HS256, secret_key)
                    .compact();

            return token;
        }
        return null;
    }

    private boolean authenticate(String user, String pass) {
        return "admin".equals(user) && "admin123".equals(pass);
    }
}
