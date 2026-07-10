package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*
import javax.servlet.http.HttpServletRequest

// Vulnerable: XSS via servlet parameter in HTML
fun handler00026(request: HttpServletRequest): String {
    val msg = request.getParameter("msg")
    return "<html><body><p>$msg</p></body></html>"
}
