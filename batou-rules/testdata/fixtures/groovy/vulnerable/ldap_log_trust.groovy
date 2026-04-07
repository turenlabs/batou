// Vulnerable: LDAP injection, log injection, trust boundary, cookie injection, open redirect
import javax.naming.directory.InitialDirContext

class VulnerableController {
    // LDAP injection via InitialDirContext.search
    def searchUser() {
        def filter = request.getParameter("filter")
        InitialDirContext ctx = new InitialDirContext(env)
        ctx.search("ou=users", filter, controls)
    }

    // LDAP injection via Spring LdapTemplate
    def searchLdap() {
        def query = params.query
        ldapTemplate.search("ou=people", query, mapper)
    }

    // Log injection via Logger.getLogger
    def logAction() {
        def action = request.getParameter("action")
        Logger.getLogger("app").info(action)
    }

    // Log injection via SLF4J LoggerFactory
    def logEvent() {
        def event = request.getParameter("event")
        LoggerFactory.getLogger("app").warn(event)
    }

    // Trust boundary - session.setAttribute
    def storeInSession() {
        def data = request.getParameter("data")
        session.setAttribute("userData", data)
    }

    // Cookie injection - response.addCookie
    def setCookie() {
        def pref = request.getParameter("pref")
        response.addCookie(new Cookie("pref", pref))
    }

    // Open redirect via Grails redirect(url:)
    def doRedirect() {
        def url = params.returnUrl
        redirect(url: url)
    }
}
