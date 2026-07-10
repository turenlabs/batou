package bench

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

// Vulnerable: open redirect via servlet sendRedirect
fun handler00106(request: HttpServletRequest, response: HttpServletResponse) {
    val target = request.getParameter("target")
    response.sendRedirect(target)
}
