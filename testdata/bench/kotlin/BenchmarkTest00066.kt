package bench

import javax.servlet.http.HttpServletRequest
import java.io.File

// Vulnerable: path traversal via servlet parameter
fun handler00066(request: HttpServletRequest): String {
    val path = request.getParameter("file")
    return File("/var/www/static/$path").readText()
}
