package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Vulnerable: SQL injection via header value
suspend fun handler00010(call: ApplicationCall) {
    val tenant = call.request.headers["X-Tenant-ID"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    conn.createStatement().executeQuery("SELECT * FROM data WHERE tenant_id = '$tenant'")
    call.respondText("OK")
}
