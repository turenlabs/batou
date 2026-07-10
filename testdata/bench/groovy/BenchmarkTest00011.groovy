import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:h2:mem:test")
def search = request.getParameter("q")
def results = sql.rows("SELECT * FROM items WHERE title LIKE '%" + search + "%'")
