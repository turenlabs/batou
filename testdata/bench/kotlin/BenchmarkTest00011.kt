package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: parameterized query with prepared statement
suspend fun handler00011(call: ApplicationCall) {
    val id = call.parameters["id"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setString(1, id)
    val rs = stmt.executeQuery()
    call.respondText(rs.toString())
}
