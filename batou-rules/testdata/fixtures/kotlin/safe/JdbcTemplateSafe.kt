package com.example.safe

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.expression.spel.support.SimpleEvaluationContext

@RestController
class SafeController(private val jdbcTemplate: JdbcTemplate) {

    // Safe: JdbcTemplate with parameterized query
    @GetMapping("/users")
    fun findUsers(@RequestParam name: String): List<Map<String, Any>> {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ?", name)
    }

    // Safe: JdbcTemplate.queryForObject with parameter
    @GetMapping("/count")
    fun countByStatus(@RequestParam status: String): Int? {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM users WHERE status = ?", Int::class.java, status)
    }

    // Safe: JdbcTemplate.update with parameter
    @PostMapping("/users/delete")
    fun deleteUser(@RequestParam id: Int) {
        jdbcTemplate.update("DELETE FROM users WHERE id = ?", id)
    }

    // Safe: SpEL with SimpleEvaluationContext (restricted)
    @GetMapping("/spel")
    fun evalSpel(@RequestParam expr: String): Any? {
        val parser = SpelExpressionParser()
        val context = SimpleEvaluationContext.forReadOnlyDataBinding().build()
        val expression = parser.parseExpression(expr)
        return expression.getValue(context)
    }

    // Safe: Class.forName with allowlist
    @GetMapping("/reflect")
    fun instantiate(@RequestParam className: String): Any? {
        val allowed = setOf("com.example.UserDTO", "com.example.ProductDTO")
        if (className !in allowed) throw IllegalArgumentException("Not allowed")
        val clazz = Class.forName(className)
        return clazz.getDeclaredConstructor().newInstance()
    }

    // Safe: PreparedStatement (parameterized)
    @PostMapping("/exec")
    fun execSafe(@RequestParam id: Int) {
        val conn = jdbcTemplate.dataSource?.connection
        val stmt = conn?.prepareStatement("SELECT * FROM users WHERE id = ?")
        stmt?.setInt(1, id)
        stmt?.executeQuery()
    }
}
