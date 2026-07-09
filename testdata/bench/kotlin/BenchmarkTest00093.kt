package bench

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

// Safe: Jackson deserialization to specific typed class (no polymorphism)
data class OrderRequest93(val item: String, val quantity: Int)

suspend fun handler00093(call: ApplicationCall) {
    val body = call.receiveText()
    val mapper = ObjectMapper()
    val order = mapper.readValue<OrderRequest93>(body)
    call.respondText("Order: ${order.item}")
}
