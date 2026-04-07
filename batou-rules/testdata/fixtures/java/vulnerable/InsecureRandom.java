package com.example.vulnerable;

import java.util.Random;
import javax.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InsecureRandom {

    private final Random random = new Random();

    @GetMapping("/generate-token")
    public String generateSessionToken(HttpSession session) {
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        session.setAttribute("csrf_token", token.toString());
        return token.toString();
    }

    @GetMapping("/reset-code")
    public String generatePasswordResetCode() {
        Random rng = new Random(System.currentTimeMillis());
        int otp = rng.nextInt(900000) + 100000;
        return String.valueOf(otp);
    }

    public String generateApiKey() {
        Random gen = new Random();
        byte[] keyBytes = new byte[24];
        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) gen.nextInt(256);
        }
        return java.util.Base64.getEncoder().encodeToString(keyBytes);
    }
}
