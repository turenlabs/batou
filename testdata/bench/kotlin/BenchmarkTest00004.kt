package bench

import javax.servlet.http.HttpServletRequest
import java.sql.DriverManager

// Vulnerable: SQL injection via servlet request parameter
fun handler00004(request: HttpServletRequest) {
    val id = request.getParameter("id")
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().executeQuery("SELECT * FROM orders WHERE id = $id")
}
