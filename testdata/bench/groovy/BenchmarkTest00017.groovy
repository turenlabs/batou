class AdminController {
    def dataSource
    def deleteItem() {
        def sql = new groovy.sql.Sql(dataSource)
        def itemId = params.itemId
        sql.execute("DELETE FROM items WHERE id = ${itemId}")
        redirect(action: "list")
    }
}
