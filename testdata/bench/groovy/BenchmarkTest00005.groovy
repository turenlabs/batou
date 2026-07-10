class UserController {
    def dataSource
    def show() {
        def sql = new groovy.sql.Sql(dataSource)
        def id = params.id
        def user = sql.firstRow("SELECT * FROM users WHERE id = ${id}")
        render user as JSON
    }
}
