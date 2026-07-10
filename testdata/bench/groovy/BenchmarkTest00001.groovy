import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/app", "root", "", "com.mysql.jdbc.Driver")
def name = params.name
sql.execute("SELECT * FROM users WHERE name = '${name}'")
