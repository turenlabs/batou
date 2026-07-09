package bench

import (
	"io"
	"net"
	"net/http"
)

// IP parse validation
func Handler00076(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
		http.Error(w, "forbidden", 403)
		return
	}
	resp, _ := http.Get("http://" + ip.String() + ":8080/api")
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
