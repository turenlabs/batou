<?php
// Safe: LDAP with proper escaping

function ldap_authenticate($username, $password) {
    $conn = ldap_connect("ldap://ldap.example.com");

    // Safe: ldap_escape used
    $safe_user = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
    $filter = "(uid=" . $safe_user . ")";
    $result = ldap_search($conn, "dc=example,dc=com", $filter);

    $safe_dn = ldap_escape($username, '', LDAP_ESCAPE_DN);
    ldap_bind($conn, "uid=" . $safe_dn . ",ou=people,dc=example,dc=com", $password);
}
