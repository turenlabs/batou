import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/admin")
def results = sql.rows("SELECT COUNT(*) FROM users")
