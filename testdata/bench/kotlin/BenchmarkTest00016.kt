package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: integer-only validated input used in query
suspend fun handler00016(call: ApplicationCall) {
    val sort = call.parameters["sort"]
    val allowed = listOf("name", "date", "id")
    val safeSort = if (sort in allowed) sort else "id"
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val rs = conn.createStatement().executeQuery("SELECT * FROM items ORDER BY $safeSort")
    call.respondText(rs.toString())
}
