package bench

import (
	"encoding/xml"
	"fmt"
	"net/http"
)

// Typed XML decode
type safeXML133 struct {
	XMLName xml.Name `xml:"item"`
	Value   string   `xml:"value"`
}

func Handler00133(w http.ResponseWriter, r *http.Request) {
	var item safeXML133
	xml.NewDecoder(r.Body).Decode(&item)
	fmt.Fprintf(w, "value: %s", item.Value)
}
