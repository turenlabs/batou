package com.example.safe;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Transaction;
import org.neo4j.driver.Result;
import org.springframework.data.neo4j.core.Neo4jClient;

public class Neo4jCypherParameterized extends HttpServlet {

    private Driver driver;
    private Neo4jClient neo4jClient;

    // Safe: user values pass through the parameters map, Cypher is a literal.
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String name = request.getParameter("name");
        Map<String, Object> params = new HashMap<>();
        params.put("name", name);
        try (Session session = driver.session()) {
            Result result = session.run("MATCH (u:User {name: $name}) RETURN u", params);
        }
    }

    // Safe: explicit begin/commit transaction with parameterized Cypher.
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String id = request.getParameter("id");
        Map<String, Object> params = new HashMap<>();
        params.put("id", id);
        try (Session session = driver.session()) {
            Transaction tx = session.beginTransaction();
            tx.run("MATCH (n) WHERE id(n) = $id DELETE n", params);
            tx.commit();
        }
    }

    // Safe: Spring Data Neo4j Neo4jClient with .bind(...).to("param") binding.
    public void searchPosts(HttpServletRequest request) {
        String title = request.getParameter("title");
        neo4jClient
                .query("MATCH (p:Post) WHERE p.title = $title RETURN p")
                .bind(title).to("title")
                .fetch()
                .all();
    }
}
