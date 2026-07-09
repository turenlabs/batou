package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via string interpolation in variable
suspend fun handler00006(call: ApplicationCall) {
    val table = call.parameters["table"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val sql = "SELECT COUNT(*) FROM $table"
    conn.createStatement().executeQuery(sql)
    call.respondText("OK")
}
