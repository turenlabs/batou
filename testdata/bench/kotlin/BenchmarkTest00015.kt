package bench

import javax.servlet.http.HttpServletRequest
import java.sql.DriverManager

// Safe: servlet with prepared statement
fun handler00015(request: HttpServletRequest) {
    val id = request.getParameter("id")
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM orders WHERE id = ?")
    stmt.setString(1, id)
    stmt.executeQuery()
}
