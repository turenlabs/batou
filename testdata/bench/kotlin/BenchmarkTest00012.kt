package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: parameterized query with named parameter
suspend fun handler00012(call: ApplicationCall) {
    val name = call.request.queryParameters["name"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
    stmt.setString(1, name)
    val rs = stmt.executeQuery()
    call.respondText(rs.toString())
}
