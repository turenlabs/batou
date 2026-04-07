// Safe: JNDI with namespace restriction and SpEL with SimpleEvaluationContext
import javax.naming.InitialContext
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.SimpleEvaluationContext

class SafeService {

    // Safe — JNDI lookup restricted to java:comp/ namespace
    def lookupResource(String name) {
        if (!name.startsWith("java:comp")) {
            throw new SecurityException("Invalid JNDI namespace")
        }
        def ctx = new InitialContext()
        return ctx.lookup(name)
    }

    // Safe — SpEL with SimpleEvaluationContext (read-only, no method invocation)
    def evaluateExpression(String expr) {
        def parser = new SpelExpressionParser()
        def context = SimpleEvaluationContext.forReadOnlyDataBinding().build()
        def expression = parser.parseExpression(expr)
        return expression.getValue(context)
    }

    // Safe — HTML output with OWASP Encoder
    def renderHtml(String userInput) {
        def safe = Encode.forHtml(userInput)
        return "<div>${safe}</div>"
    }
}
