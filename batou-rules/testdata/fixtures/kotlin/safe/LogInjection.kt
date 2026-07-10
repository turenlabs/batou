package com.example.safe

import javax.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import timber.log.Timber

private val logger = LoggerFactory.getLogger("auth")

class LogInjectionSafe {

    // Safe: CRLF stripped before logging
    fun onLogin(req: HttpServletRequest) {
        val user = req.getParameter("user")
        val clean = user.replace("\n", "").replace("\r", "")
        logger.warn("login attempt: {}", clean)
    }

    // Safe: structured logging with parameter binding (no concatenation)
    fun onDebug(req: HttpServletRequest) {
        val user = req.getParameter("user")
        val sanitized = user.replace("[\r\n]".toRegex(), "_")
        logger.debug("processing: {}", sanitized)
    }

    // Safe: Timber with sanitized input
    fun onTimber(req: HttpServletRequest) {
        val user = req.getParameter("user")
        val safe = user.replace("\n", "_").replace("\r", "_")
        Timber.d("user: %s", safe)
    }

    // Safe: String.format with constant format string; tainted arg sanitized before logging
    fun onFormat(req: HttpServletRequest) {
        val user = req.getParameter("user")
        val safe = user.replace("\n", "_").replace("\r", "_")
        val msg = String.format("user=%s", safe)
        logger.info(msg)
    }
}
