import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:h2:mem:test")
def category = request.getParameter("category")
def results = sql.rows("SELECT * FROM products WHERE category = ?", [category])
