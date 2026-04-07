package vulnerable

import (
	"fmt"
	"net/http"

	"github.com/go-ldap/ldap/v3"
)

// VULN: LDAP injection via user-controlled DN in Bind and NewAddRequest.
// Attacker can inject LDAP metacharacters to manipulate directory operations.

func HandleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	conn, err := ldap.DialURL("ldap://localhost:389")
	if err != nil {
		http.Error(w, "ldap connect failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// DN injection: username is unsanitized
	dn := fmt.Sprintf("uid=%s,ou=people,dc=example,dc=com", username)
	err = conn.Bind(dn, password)
	if err != nil {
		http.Error(w, "auth failed", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("authenticated"))
}

func HandleLDAPCreateUser(w http.ResponseWriter, r *http.Request) {
	cn := r.FormValue("cn")

	conn, _ := ldap.DialURL("ldap://localhost:389")
	defer conn.Close()

	// DN injection in add request
	dn := "cn=" + cn + ",ou=people,dc=example,dc=com"
	addReq := ldap.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson"})
	addReq.Attribute("cn", []string{cn})
	conn.Add(addReq)
}
