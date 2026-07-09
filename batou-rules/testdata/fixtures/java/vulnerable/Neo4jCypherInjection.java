package com.example.vulnerable;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Transaction;
import org.neo4j.driver.Result;
import org.neo4j.driver.async.AsyncSession;
import org.springframework.data.neo4j.core.Neo4jClient;

public class Neo4jCypherInjection extends HttpServlet {

    private Driver driver;
    private Neo4jClient neo4jClient;

    // CWE-943: Session.run with concatenated Cypher
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String name = request.getParameter("name");
        try (Session session = driver.session()) {
            String cypher = "MATCH (u:User {name: '" + name + "'}) RETURN u";
            Result result = session.run(cypher);
        }
    }

    // CWE-943: Transaction.run with concatenated Cypher
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String label = request.getParameter("label");
        try (Session session = driver.session()) {
            String cypher = "CREATE (:" + label + " {id: 1})";
            Transaction tx = session.beginTransaction();
            tx.run(cypher);
            tx.commit();
        }
    }

    // CWE-943: AsyncSession.runAsync with concatenated Cypher
    public void deleteById(HttpServletRequest request) {
        String id = request.getParameter("id");
        AsyncSession asyncSession = driver.asyncSession();
        String cypher = "MATCH (n) WHERE id(n) = " + id + " DELETE n";
        asyncSession.runAsync(cypher);
    }

    // CWE-943: Spring Data Neo4j Neo4jClient.query with concatenated Cypher
    public void searchPosts(HttpServletRequest request) {
        String title = request.getParameter("title");
        String cypher = "MATCH (p:Post) WHERE p.title = '" + title + "' RETURN p";
        neo4jClient.query(cypher).fetch().all();
    }
}
