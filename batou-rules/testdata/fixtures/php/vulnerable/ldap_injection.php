<?php
// GTSS-PHP-010: LDAP injection

function ldap_authenticate($username, $password) {
    $conn = ldap_connect("ldap://ldap.example.com");

    // Vulnerable: unescaped user input in LDAP filter
    $filter = "(uid=" . $username . ")";
    $result = ldap_search($conn, "dc=example,dc=com", $filter);

    // Vulnerable: unescaped user input in LDAP bind DN
    ldap_bind($conn, "uid=" . $username . ",ou=people,dc=example,dc=com", $password);
}
