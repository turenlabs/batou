package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via receiveText body
suspend fun handler00008(call: ApplicationCall) {
    val filter = call.receiveText()
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().executeQuery("SELECT * FROM logs WHERE message LIKE '%${filter}%'")
    call.respondText("OK")
}
