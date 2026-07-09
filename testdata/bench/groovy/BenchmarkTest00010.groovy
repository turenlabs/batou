import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/shop")
def status = params.status
def orderId = params.order_id
sql.executeUpdate("UPDATE orders SET status = ? WHERE id = ?", [status, orderId])
