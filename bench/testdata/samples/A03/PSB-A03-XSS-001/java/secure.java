// PSB-A03-XSS-001: Comment display
// CWE: CWE-79
// Expected: (none - secure)
package com.example.blog;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;
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
            String safeAuthor = HtmlUtils.htmlEscape(c.get("author").toString());
            String safeText = HtmlUtils.htmlEscape(c.get("text").toString()).replace("\n", "<br>");
            out.println("<div class=\"comment\">");
            out.println("<strong>" + safeAuthor + "</strong>");
            out.println("<span>" + c.get("created_at") + "</span>");
            out.println("<p>" + safeText + "</p>");
            out.println("</div>");
        }
        out.println("</body></html>");
    }
}
