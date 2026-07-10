import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:postgresql://localhost/app")
def dept = request.getParameter("department")
sql.eachRow("SELECT * FROM employees WHERE dept = '${dept}'") { row ->
    println row.name
}
