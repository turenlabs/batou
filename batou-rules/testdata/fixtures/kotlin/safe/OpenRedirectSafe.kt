package com.example.safe

import java.net.URI
import javax.ws.rs.core.Response
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class OpenRedirectSafeController {

    private val allowedHosts = setOf("example.com", "www.example.com")

    // Safe: the URI is a compile-time constant
    @GetMapping("/redirect-const")
    fun redirectConst(): ResponseEntity<Any> {
        val headers = HttpHeaders()
        headers.setLocation(URI.create("https://example.com/home"))
        return ResponseEntity(headers, null, 302)
    }

    // Safe: host is validated against an allow-list before redirect
    @GetMapping("/redirect")
    fun redirectValidated(@RequestParam target: String): Response {
        val uri = URI.create(target)
        if (uri.host !in allowedHosts) {
            return Response.status(400).build()
        }
        return Response.seeOther(uri).build()
    }
}
