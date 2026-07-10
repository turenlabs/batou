package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: prepared statement with multiple parameters
suspend fun handler00018(call: ApplicationCall) {
    val name = call.parameters["name"]
    val age = call.parameters["age"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ? AND age = ?")
    stmt.setString(1, name)
    stmt.setString(2, age)
    stmt.executeQuery()
    call.respondText("OK")
}
