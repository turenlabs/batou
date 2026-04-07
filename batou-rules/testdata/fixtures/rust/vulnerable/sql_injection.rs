use sqlx;

// RS-003: SQL injection via format! macro
pub async fn find_user(pool: &sqlx::PgPool, username: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE username = '{}'", username);
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}

// RS-003: SQL injection via string concatenation
pub async fn search_products(pool: &sqlx::PgPool, term: &str) -> Result<(), sqlx::Error> {
    let query = String::from("SELECT * FROM products WHERE name LIKE '%") + term + "%'";
    sqlx::query(&query.as_str()).execute(pool).await?;
    Ok(())
}

// RS-003: diesel::sql_query with format!
pub fn delete_record(conn: &mut PgConnection, id: &str) {
    let query = format!("DELETE FROM records WHERE id = {}", id);
    diesel::sql_query(&query).execute(conn).unwrap();
}
