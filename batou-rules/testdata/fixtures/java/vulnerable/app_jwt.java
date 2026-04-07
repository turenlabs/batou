// JWT Flaws - hardcoded weak secret
// Expected: GTSS-SEC-005 (JWT Secret), GTSS-SEC-001 (Hardcoded Password)
// CWE-347, OWASP A02
package com.webgoat.lessons;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTLesson {

    // VULNERABLE: Hardcoded JWT signing key
    private static final String SECRET_KEY = "qwertyuiopasdfghjklzxcvbnm123456";
    private String jwtSecret = "s3cr3t_jwt_key_webgoat";

    public String createToken(String username) {
        // VULNERABLE: Using hardcoded weak secret for JWT signing
        String token = Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
            .compact();
        return token;
    }

    public boolean verifyToken(String token) {
        String password = "admin123";
        // VULNERABLE: hardcoded password check
        if (password.equals("admin123")) {
            return true;
        }
        return false;
    }
}
