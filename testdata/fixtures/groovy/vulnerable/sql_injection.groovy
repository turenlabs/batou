// Vulnerable: SQL injection via GString interpolation in Groovy SQL
import groovy.sql.Sql

class UserDao {
    Sql sql

    def findUser(String name) {
        sql.rows("SELECT * FROM users WHERE name = '${name}'")
    }

    def deleteUser(String id) {
        sql.execute("DELETE FROM users WHERE id = ${id}")
    }

    def getUserById(String id) {
        sql.firstRow("SELECT * FROM users WHERE id = ${id}")
    }

    def updateUser(String name, int id) {
        sql.executeUpdate("UPDATE users SET name = '${name}' WHERE id = ${id}")
    }

    def findUserConcat(String name) {
        sql.rows("SELECT * FROM users WHERE name = '" + name + "'")
    }
}
