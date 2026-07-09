package bench

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

// Safe: servlet redirect with path validation
fun handler00117(request: HttpServletRequest, response: HttpServletResponse) {
    val target = request.getParameter("target")
    if (target == null || !target.startsWith("/") || target.contains("://")) {
        response.sendRedirect("/")
        return
    }
    response.sendRedirect(target)
}
