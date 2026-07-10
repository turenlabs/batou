package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via string template with call.receive
suspend fun handler00003(call: ApplicationCall) {
    val body = call.receive<Map<String, String>>()
    val search = body["search"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().executeQuery("SELECT * FROM products WHERE name LIKE '%${search}%'")
    call.respondText("OK")
}
