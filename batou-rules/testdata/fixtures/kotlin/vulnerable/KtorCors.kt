package com.example.vulnerable

import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.http.*

// Vulnerable: CORS allows any host with credentials
fun Application.configureCors() {
    install(CORS) {
        anyHost()
        allowCredentials = true
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
    }
}
