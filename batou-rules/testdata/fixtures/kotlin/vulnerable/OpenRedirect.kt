package com.example.vulnerable

import java.net.URI
import javax.servlet.RequestDispatcher
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.ws.rs.core.Response
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.QueryValue

@RestController
class OpenRedirectController {

    // Vulnerable: Spring HttpHeaders.setLocation with tainted URI (open redirect)
    @GetMapping("/redirect1")
    fun redirectHeader(@RequestParam target: String): ResponseEntity<Any> {
        val headers = HttpHeaders()
        headers.setLocation(URI.create(target))
        return ResponseEntity(headers, null, 302)
    }

    // Vulnerable: Spring ResponseEntity.created with tainted URI (open redirect via 201 Location)
    @GetMapping("/created")
    fun resourceCreated(@RequestParam target: String): ResponseEntity<Any> {
        return ResponseEntity.created(URI.create(target)).build()
    }

    // Vulnerable: JAX-RS Response.seeOther with tainted URI
    fun jaxrsSeeOther(target: String): Response {
        return Response.seeOther(URI.create(target)).build()
    }

    // Vulnerable: JAX-RS Response.temporaryRedirect with tainted URI
    fun jaxrsTempRedirect(target: String): Response {
        return Response.temporaryRedirect(URI.create(target)).build()
    }

    // Vulnerable: RequestDispatcher.forward with request-controlled path
    fun forwardRequest(request: HttpServletRequest, response: HttpServletResponse) {
        val target = request.getParameter("next")
        val dispatcher: RequestDispatcher = request.getRequestDispatcher(target)
        dispatcher.forward(request, response)
    }
}

@Controller("/micronaut")
class MicronautRedirectController {

    // Vulnerable: Micronaut HttpResponse.redirect with tainted URI
    @Get("/redirect")
    fun redirect(@QueryValue target: String): HttpResponse<Any> {
        return HttpResponse.redirect<Any>(URI.create(target))
    }

    // Vulnerable: Micronaut HttpResponse.seeOther with tainted URI
    @Get("/see")
    fun see(@QueryValue target: String): HttpResponse<Any> {
        return HttpResponse.seeOther<Any>(URI.create(target))
    }
}
