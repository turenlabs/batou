package com.example.vulnerable

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
import javax.script.ScriptEngineManager
import org.springframework.expression.spel.standard.SpelExpressionParser

@RestController
class VulnerableController(private val jdbcTemplate: JdbcTemplate) {

    // Vulnerable: JdbcTemplate.query with string concatenation
    @GetMapping("/users")
    fun findUsers(@RequestParam name: String): List<Map<String, Any>> {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'")
    }

    // Vulnerable: JdbcTemplate.queryForObject with template
    @GetMapping("/user/{id}")
    fun findUser(@PathVariable id: String): Map<String, Any>? {
        return jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = $id")
    }

    // Vulnerable: JdbcTemplate.update with concatenation
    @PostMapping("/users/delete")
    fun deleteUser(@RequestParam id: String) {
        jdbcTemplate.update("DELETE FROM users WHERE id = " + id)
    }

    // Vulnerable: JdbcTemplate.execute with concatenation
    @PostMapping("/tables/create")
    fun createTable(@RequestParam tableName: String) {
        jdbcTemplate.execute("CREATE TABLE " + tableName + " (id INT)")
    }

    // Vulnerable: JdbcTemplate.batchUpdate with concatenation
    @PostMapping("/users/batch")
    fun batchDelete(@RequestParam ids: String) {
        jdbcTemplate.batchUpdate("DELETE FROM users WHERE id IN (" + ids + ")")
    }

    // Vulnerable: JdbcTemplate.queryForObject with concatenation
    @GetMapping("/count")
    fun countByStatus(@RequestParam status: String): Int? {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM users WHERE status = '" + status + "'", Int::class.java)
    }

    // Vulnerable: ScriptEngine.eval with user input
    @PostMapping("/eval")
    fun evalScript(@RequestBody script: String): Any? {
        val engine = ScriptEngineManager().getEngineByName("js")
        return engine.eval(script)
    }

    // Vulnerable: Spring SpEL with user input
    @GetMapping("/spel")
    fun evalSpel(@RequestParam expr: String): Any? {
        val parser = SpelExpressionParser()
        val expression = parser.parseExpression(expr)
        return expression.value
    }

    // Vulnerable: Class.forName with user input
    @GetMapping("/reflect")
    fun instantiate(@RequestParam className: String): Any? {
        val clazz = Class.forName(className)
        return clazz.getDeclaredConstructor().newInstance()
    }

    // Vulnerable: Method.invoke with user-controlled method name
    @PostMapping("/invoke")
    fun invokeMethod(@RequestParam className: String, @RequestParam methodName: String): Any? {
        val clazz = Class.forName(className)
        val method = clazz.getMethod(methodName)
        return method.invoke(null)
    }

    // Vulnerable: Statement.execute with concatenation
    @PostMapping("/exec")
    fun execRaw(@RequestParam query: String) {
        val conn = jdbcTemplate.dataSource?.connection
        val stmt = conn?.createStatement()
        stmt?.execute("SELECT * FROM " + query)
    }

    // Vulnerable: Connection.prepareCall with concatenation
    @PostMapping("/call")
    fun callProc(@RequestParam proc: String) {
        val conn = jdbcTemplate.dataSource?.connection
        conn?.prepareCall("{call " + proc + "}")
    }

    // Vulnerable: ProcessBuilder.command with user input
    @PostMapping("/run")
    fun runCommand(@RequestParam cmd: String) {
        val pb = ProcessBuilder()
        pb.command(cmd.split(" "))
    }

    // Vulnerable: session.setAttribute with tainted data
    @PostMapping("/session")
    fun setSession(@RequestParam role: String, request: javax.servlet.http.HttpServletRequest) {
        request.session.setAttribute("role", role)
    }
}
