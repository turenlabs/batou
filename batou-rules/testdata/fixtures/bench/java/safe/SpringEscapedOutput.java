package com.example.safe;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;
import java.util.Map;

@RestController
public class SpringEscapedOutput {

    // SAFE: JSON response (Spring auto-serializes, no HTML injection)
    @GetMapping("/api/search")
    public Map<String, Object> search(@RequestParam String q) {
        return Map.of("query", q, "results", java.util.List.of());
    }

    // SAFE: HtmlUtils.htmlEscape for explicit escaping
    @GetMapping("/api/preview")
    public Map<String, String> preview(@RequestParam String content) {
        String safeContent = HtmlUtils.htmlEscape(content);
        return Map.of("html", safeContent);
    }

    // SAFE: Thymeleaf th:text auto-escapes (returns template name)
    @GetMapping("/profile")
    public String profilePage(@RequestParam String username,
                              org.springframework.ui.Model model) {
        model.addAttribute("username", username);
        return "profile";
    }

    // SAFE: ResponseEntity with plain text content type
    @GetMapping("/api/echo")
    public org.springframework.http.ResponseEntity<String> echo(@RequestParam String msg) {
        return org.springframework.http.ResponseEntity.ok()
                .header("Content-Type", "text/plain")
                .body(msg);
    }
}
