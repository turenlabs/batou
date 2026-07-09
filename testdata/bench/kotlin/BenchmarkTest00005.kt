package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via string template with ORDER BY
suspend fun handler00005(call: ApplicationCall) {
    val sort = call.parameters["sort"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val rs = conn.createStatement().executeQuery("SELECT * FROM items ORDER BY $sort")
    call.respondText(rs.toString())
}
