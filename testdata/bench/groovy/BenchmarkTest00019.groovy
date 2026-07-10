import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:postgresql://localhost/blog")
def title = params.title
def body = params.body
sql.execute("INSERT INTO posts (title, body) VALUES ('${title}', '${body}')")
