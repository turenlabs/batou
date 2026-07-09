import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/auth")
def username = params.username
def password = params.password
def user = sql.firstRow("SELECT * FROM accounts WHERE user = ? AND pass = ?", [username, password])
