package com.example.vulnerable;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Repository
public class SqliHibernate {

    @PersistenceContext
    private EntityManager entityManager;

    @GetMapping("/search")
    public List<?> searchUsers(HttpServletRequest request) {
        String username = request.getParameter("username");
        String hql = "FROM User u WHERE u.username = '" + username + "'";
        return entityManager.createQuery(hql).getResultList();
    }

    @GetMapping("/admin/query")
    public List<?> adminQuery(HttpServletRequest request) {
        String table = request.getParameter("entity");
        String nativeSQL = "SELECT * FROM " + table + " WHERE active = 1";
        return entityManager.createNativeQuery(nativeSQL).getResultList();
    }
}
