def call(Map config) {
    def dbName = config.database
    def sql = Sql.newInstance("jdbc:mysql://db:3306/${dbName}")
    def table = config.table
    sql.execute("SELECT COUNT(*) FROM ${table}")
}
