package com.example.vulnerable;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Demonstrates Spring controller XSS via @ResponseBody returning
 * string-concatenated HTML with user input.
 */
@RestController
public class XssSpringController {

    @GetMapping("/greet")
    public String greet(@RequestParam String name) {
        return "<h1>Hello " + name + "</h1>";
    }

    @GetMapping("/search")
    @ResponseBody
    public String search(@RequestParam String q) {
        return "<div class='results'>" + q + "</div>";
    }

    @GetMapping("/profile")
    public String profile(@RequestParam String user) {
        String html = String.format("<div class='profile'><h2>%s</h2></div>", user);
        return html;
    }
}
