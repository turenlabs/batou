import javax.servlet.http.*;

public class HeaderInjection extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        // VULNERABLE: setting header from request parameter without CRLF sanitization
        String customVal = request.getParameter("val");
        response.setHeader("X-Custom", request.getParameter("val"));
        response.addHeader("X-User", request.getParameter("user"));
    }
}
