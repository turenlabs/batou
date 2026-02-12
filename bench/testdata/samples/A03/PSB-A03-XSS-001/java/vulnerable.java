// PSB-A03-XSS-001: Comment display
// CWE: CWE-79
// Expected: GTSS-XSS-001, GTSS-XSS-002
package com.example.blog;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

@RestController
public class CommentController {
    private final JdbcTemplate jdbc;

    public CommentController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/posts/{id}/comments")
    public void showComments(@PathVariable Long id, HttpServletResponse response) throws Exception {
        List<Map<String, Object>> comments = jdbc.queryForList(
            "SELECT author, text, created_at FROM comments WHERE post_id = ? ORDER BY created_at", id);

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body><h1>Comments</h1>");
        for (Map<String, Object> c : comments) {
            out.println("<div class=\"comment\">");
            out.println("<strong>" + c.get("author") + "</strong>");
            out.println("<span>" + c.get("created_at") + "</span>");
            String text = c.get("text").toString().replace("\n", "<br>");
            out.println("<p>" + text + "</p>");
            out.println("</div>");
        }
        out.println("</body></html>");
    }
}
