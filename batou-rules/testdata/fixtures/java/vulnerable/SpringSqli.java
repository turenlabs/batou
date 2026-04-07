package com.example.vulnerable;

import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class SpringSqli {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/users")
    public List<Map<String, Object>> findUsers(@RequestParam String name) {
        String sql = "SELECT * FROM users WHERE name LIKE '%" + name + "%'";
        return jdbcTemplate.queryForList(sql);
    }

    @GetMapping("/orders")
    public List<Map<String, Object>> getOrders(HttpServletRequest request) {
        String status = request.getParameter("status");
        String sort = request.getParameter("sort");
        String query = "SELECT * FROM orders WHERE status = '" + status + "' ORDER BY " + sort;
        return jdbcTemplate.queryForList(query);
    }

    @GetMapping("/products")
    public List<Map<String, Object>> searchProducts(@RequestParam String category) {
        return jdbcTemplate.queryForList(
                "SELECT * FROM products WHERE category = '" + category + "'"
        );
    }
}
