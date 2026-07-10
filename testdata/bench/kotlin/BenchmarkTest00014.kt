package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: prepared statement with receive body
suspend fun handler00014(call: ApplicationCall) {
    val body = call.receive<Map<String, String>>()
    val search = body["search"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ?")
    stmt.setString(1, "%$search%")
    stmt.executeQuery()
    call.respondText("OK")
}
