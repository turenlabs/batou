// Safe: Parameterized SQL queries in Groovy
import groovy.sql.Sql

class UserDao {
    Sql sql

    def findUser(String name) {
        sql.rows("SELECT * FROM users WHERE name = ?", [name])
    }

    def deleteUser(int id) {
        sql.execute("DELETE FROM users WHERE id = ?", [id])
    }

    def getUserById(int id) {
        sql.firstRow("SELECT * FROM users WHERE id = ?", [id])
    }

    def updateUser(String name, int id) {
        sql.executeUpdate("UPDATE users SET name = ? WHERE id = ?", [name, id])
    }

    def findByStatus(String status) {
        sql.rows("SELECT * FROM users WHERE status = :status", [status: status])
    }
}
