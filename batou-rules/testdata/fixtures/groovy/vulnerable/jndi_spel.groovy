// Vulnerable: JNDI lookup and SpEL injection with user-controlled input
import javax.naming.InitialContext
import org.springframework.expression.spel.standard.SpelExpressionParser

class VulnerableService {

    // JNDI injection — user controls lookup name
    def lookupResource(String userInput) {
        def ctx = new InitialContext()
        def resource = ctx.lookup(userInput)
        return resource
    }

    // SpEL injection — user controls expression
    def evaluateExpression(String userExpression) {
        def parser = new SpelExpressionParser()
        def expr = parser.parseExpression(userExpression)
        return expr.getValue()
    }

    // Trust boundary — tainted data injected into script binding
    def runScript(String userInput) {
        def binding = new Binding()
        binding.setVariable("data", userInput)
        def shell = new GroovyShell(binding)
        return shell.evaluate("process(data)")
    }
}
