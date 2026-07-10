package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via string concatenation in Ktor
suspend fun handler00002(call: ApplicationCall) {
    val name = call.request.queryParameters["name"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val query = "SELECT * FROM users WHERE name = '" + name + "'"
    val rs = conn.createStatement().executeQuery(query)
    call.respondText(rs.toString())
}
