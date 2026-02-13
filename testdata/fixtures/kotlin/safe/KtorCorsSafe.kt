package com.example.safe

import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.http.*

// Safe: CORS with specific allowed hosts
fun Application.configureCors() {
    install(CORS) {
        allowHost("trusted.example.com", schemes = listOf("https"))
        allowHost("api.example.com", schemes = listOf("https"))
        allowCredentials = true
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
    }
}
