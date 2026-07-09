package bench

import io.ktor.server.application.*
import io.ktor.server.response.*
import java.sql.DriverManager

// Safe: header value used with prepared statement
suspend fun handler00020(call: ApplicationCall) {
    val tenant = call.request.headers["X-Tenant-ID"]
    val conn = DriverManager.getConnection("jdbc:sqlite::memory:")
    val stmt = conn.prepareStatement("SELECT * FROM data WHERE tenant_id = ?")
    stmt.setString(1, tenant)
    stmt.executeQuery()
    call.respondText("OK")
}
