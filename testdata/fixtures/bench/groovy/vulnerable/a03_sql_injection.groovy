// Source: CWE-89 - SQL Injection via GString in Groovy
// Expected: BATOU-GVY
// OWASP: A03:2021 - Injection (SQL Injection)

import groovy.sql.Sql

def username = args[0]
def sql = Sql.newInstance("jdbc:mysql://localhost/app", "root", "", "com.mysql.jdbc.Driver")
def query = "SELECT * FROM users WHERE name = '${username}'"
def rows = sql.rows(query)
rows.each { println it }
