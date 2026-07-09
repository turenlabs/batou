package com.example.vulnerable

import javax.servlet.http.HttpServletRequest
import org.slf4j.LoggerFactory
import timber.log.Timber

private val logger = LoggerFactory.getLogger("auth")

class LogInjectionController {

    // Vulnerable: SLF4J Logger.warn with user-controlled concatenation (CWE-117)
    fun onLogin(req: HttpServletRequest) {
        val user = req.getParameter("user")
        logger.warn("login attempt: " + user)
    }

    // Vulnerable: Logger.debug with user input
    fun onDebug(req: HttpServletRequest) {
        val user = req.getParameter("user")
        logger.debug("processing: " + user)
    }

    // Vulnerable: Logger.trace with user input
    fun onTrace(req: HttpServletRequest) {
        val user = req.getParameter("user")
        logger.trace("trace: " + user)
    }

    // Vulnerable: System.out.println with tainted data
    fun onStdout(req: HttpServletRequest) {
        val user = req.getParameter("user")
        System.out.println("user: " + user)
    }

    // Vulnerable: System.err.println with tainted data
    fun onStderr(req: HttpServletRequest) {
        val user = req.getParameter("user")
        System.err.println("error for: " + user)
    }

    // Vulnerable: Jake Wharton's Timber with tainted data
    fun onTimber(req: HttpServletRequest) {
        val user = req.getParameter("user")
        Timber.d("debug user: " + user)
        Timber.e("error user: " + user)
        Timber.wtf("fatal: " + user)
    }

    // Vulnerable: String.format with user-controlled format string (CWE-134)
    fun onFormat(req: HttpServletRequest) {
        val fmt = req.getParameter("fmt")
        val msg = String.format(fmt)
        logger.info(msg)
    }
}
