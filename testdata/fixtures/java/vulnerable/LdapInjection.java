package com.example.vulnerable;

import java.io.IOException;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LdapInjection extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, "ldap://ldap.example.com:389");
            DirContext ctx = new InitialDirContext(env);

            String searchFilter = "(&(uid=" + username + ")(objectClass=person))";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results = ctx.search("dc=example,dc=com", searchFilter, controls);

            while (results.hasMore()) {
                SearchResult result = results.next();
                response.getWriter().println("Found: " + result.getNameInNamespace());
            }
            ctx.close();
        } catch (Exception e) {
            response.sendError(500, "LDAP error");
        }
    }
}
