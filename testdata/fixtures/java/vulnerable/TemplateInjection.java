package com.example.vulnerable;

import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Controller
public class TemplateInjection {

    private final TemplateEngine templateEngine;

    public TemplateInjection(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    @GetMapping("/preview")
    public String preview(@RequestParam String template, Model model) {
        Context context = new Context();
        context.setVariable("user", "guest");
        String result = templateEngine.process(template, context);
        model.addAttribute("content", result);
        return "preview";
    }

    @GetMapping("/greeting")
    public String greeting(HttpServletRequest request, Model model) {
        String name = request.getParameter("name");
        model.addAttribute("greeting", "Hello, " + name);
        return "greeting";
    }
}
