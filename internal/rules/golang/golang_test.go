package golang

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-GO-001: GORM Raw SQL Injection
// ==========================================================================

func TestGO001_GORMRaw_Sprintf(t *testing.T) {
	content := `package main

import "fmt"

func getUser(db *gorm.DB, name string) {
	db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)).Scan(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-001")
}

func TestGO001_GORMExec_Sprintf(t *testing.T) {
	content := `package main

import "fmt"

func deleteUser(db *gorm.DB, id string) {
	db.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %s", id))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-001")
}

func TestGO001_GORMRaw_Concat(t *testing.T) {
	content := `package main

func getUser(db *gorm.DB, name string) {
	db.Raw("SELECT * FROM users WHERE name = '" + name + "'").Scan(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-001")
}

func TestGO001_GORMWhere_Sprintf(t *testing.T) {
	content := `package main

import "fmt"

func getUser(db *gorm.DB, name string) {
	db.Where(fmt.Sprintf("name = '%s'", name)).First(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-001")
}

func TestGO001_GORMWhere_Parameterized_Safe(t *testing.T) {
	content := `package main

func getUser(db *gorm.DB, name string) {
	db.Where("name = ?", name).First(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-001")
}

func TestGO001_GORMRaw_Parameterized_Safe(t *testing.T) {
	content := `package main

func getUser(db *gorm.DB, id int) {
	db.Raw("SELECT * FROM users WHERE id = ?", id).Scan(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-001")
}

// ==========================================================================
// GTSS-GO-002: template.HTML type conversion
// ==========================================================================

func TestGO002_TemplateHTML_Variable(t *testing.T) {
	content := `package main

import "html/template"

func render(userInput string) template.HTML {
	return template.HTML(userInput)
}`
	result := testutil.ScanContent(t, "/app/render.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-002")
}

func TestGO002_TemplateJS_Variable(t *testing.T) {
	content := `package main

import "html/template"

func render(data string) template.JS {
	return template.JS(data)
}`
	result := testutil.ScanContent(t, "/app/render.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-002")
}

func TestGO002_TemplateHTMLAttr_Variable(t *testing.T) {
	content := `package main

import "html/template"

func render(attr string) template.HTMLAttr {
	return template.HTMLAttr(attr)
}`
	result := testutil.ScanContent(t, "/app/render.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-002")
}

func TestGO002_TemplateHTML_Literal_Safe(t *testing.T) {
	content := `package main

import "html/template"

func render() template.HTML {
	return template.HTML("<b>Hello</b>")
}`
	result := testutil.ScanContent(t, "/app/render.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-002")
}

// ==========================================================================
// GTSS-GO-003: ListenAndServe without TLS
// ==========================================================================

func TestGO003_ListenAndServe_NoTLS(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	http.ListenAndServe(":8080", handler)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-003")
}

func TestGO003_ListenAndServeTLS_Safe(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	http.ListenAndServeTLS(":443", "cert.pem", "key.pem", handler)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-003")
}

func TestGO003_ListenAndServe_Localhost_Safe(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	http.ListenAndServe("localhost:8080", handler)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-003")
}

func TestGO003_ListenAndServe_WithTLSConfig_Safe(t *testing.T) {
	content := `package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	srv := &http.Server{TLSConfig: cfg}
	http.ListenAndServe(":8080", handler)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-003")
}

// ==========================================================================
// GTSS-GO-005: filepath traversal
// ==========================================================================

// ==========================================================================
// GTSS-GO-004: Bind without validation
// ==========================================================================

func TestGO004_GinBindJSON_NoValidation(t *testing.T) {
	content := `package main

func createUser(c *gin.Context) {
	var user User
	c.BindJSON(&user)
	db.Create(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-004")
}

func TestGO004_GinShouldBindJSON_NoValidation(t *testing.T) {
	content := `package main

func createUser(c *gin.Context) {
	var user User
	c.ShouldBindJSON(&user)
	db.Create(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-004")
}

func TestGO004_GinBindQuery_NoValidation(t *testing.T) {
	content := `package main

func searchUsers(c *gin.Context) {
	var query SearchQuery
	c.BindQuery(&query)
	db.Find(&users, query)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-004")
}

func TestGO004_EchoBind_NoValidation(t *testing.T) {
	content := `package main

func createUser(c echo.Context) error {
	var user User
	c.Bind(&user)
	return db.Create(&user).Error
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-004")
}

func TestGO004_Safe_GinBindWithValidation(t *testing.T) {
	content := `package main

func createUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := validate.Struct(user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	db.Create(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-004")
}

func TestGO004_Safe_GinBindWithBindingTag(t *testing.T) {
	content := `package main

type User struct {
	Name  string ` + "`" + `json:"name" binding:"required,min=1,max=100"` + "`" + `
	Email string ` + "`" + `json:"email" binding:"required,email"` + "`" + `
}

func createUser(c *gin.Context) {
	var user User
	c.ShouldBindJSON(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-004")
}

func TestGO005_FilepathJoin_UserInput(t *testing.T) {
	content := `package main

import (
	"net/http"
	"path/filepath"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	path := filepath.Join("/uploads", name)
	http.ServeFile(w, r, path)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-005")
}

func TestGO005_FilepathJoin_WithHasPrefix_Safe(t *testing.T) {
	content := `package main

import (
	"net/http"
	"path/filepath"
	"strings"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	path := filepath.Join("/uploads", name)
	if !strings.HasPrefix(path, "/uploads") {
		http.Error(w, "forbidden", 403)
		return
	}
	http.ServeFile(w, r, path)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-005")
}

// ==========================================================================
// GTSS-GO-006: math/rand for crypto
// ==========================================================================

func TestGO006_MathRand_TokenGeneration(t *testing.T) {
	content := `package main

import "math/rand"

func generateToken() string {
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(rand.Intn(256))
	}
	return string(token)
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-006")
}

func TestGO006_MathRand_NonCrypto_Safe(t *testing.T) {
	content := `package main

import "math/rand"

func shuffle(items []string) {
	rand.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})
}`
	result := testutil.ScanContent(t, "/app/util.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-006")
}

// ==========================================================================
// GTSS-GO-007: Goroutine leak in HTTP handler
// ==========================================================================

func TestGO007_GoroutineLeak_NoContext(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	go func() {
		expensiveWork()
	}()
	w.Write([]byte("accepted"))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-007")
}

func TestGO007_Goroutine_WithContextDone_Safe(t *testing.T) {
	content := `package main

import (
	"context"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	go func() {
		select {
		case <-ctx.Done():
			return
		case result := <-work():
			process(result)
		}
	}()
	w.Write([]byte("accepted"))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-007")
}

// ==========================================================================
// GTSS-GO-008: Race condition in HTTP handler
// ==========================================================================

func TestGO008_SharedMap_NoMutex(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	cache[id] = time.Now()
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-008")
}

func TestGO008_SharedMap_WithMutex_Safe(t *testing.T) {
	content := `package main

import (
	"net/http"
	"sync"
)

var mu sync.Mutex

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	mu.Lock()
	cache[id] = time.Now()
	mu.Unlock()
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-008")
}

// ==========================================================================
// GTSS-GO-009: Unvalidated redirect
// ==========================================================================

func TestGO009_HTTPRedirect_UserInput(t *testing.T) {
	content := `package main

import "net/http"

func loginHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, r.URL.Query().Get("redirect"), http.StatusFound)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-009")
}

func TestGO009_GinRedirect_UserInput(t *testing.T) {
	content := `package main

func loginHandler(c *gin.Context) {
	c.Redirect(302, c.Query("redirect_url"))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-009")
}

func TestGO009_EchoRedirect_UserInput(t *testing.T) {
	content := `package main

func loginHandler(c echo.Context) error {
	return c.Redirect(302, c.QueryParam("next"))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-009")
}

func TestGO009_StaticRedirect_Safe(t *testing.T) {
	content := `package main

import "net/http"

func loginHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-009")
}

// ==========================================================================
// GTSS-GO-010: Missing CSRF
// ==========================================================================

func TestGO010_HandleFunc_FormParse_NoCSRF(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		name := r.FormValue("name")
		saveUser(name)
	})
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-010")
}

func TestGO010_HandleFunc_NoFormParse_Safe(t *testing.T) {
	content := `package main

import "net/http"

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-010")
}

func TestGO010_GinPost_NoCSRF(t *testing.T) {
	content := `package main

func main() {
	r := gin.Default()
	r.POST("/submit", func(c *gin.Context) {
		r.ParseForm()
		name := r.FormValue("name")
		saveUser(name)
	})
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-010")
}

func TestGO010_WithCSRFMiddleware_Safe(t *testing.T) {
	content := `package main

import "github.com/gorilla/csrf"

func main() {
	r := gin.Default()
	r.Use(csrf.Protect(authKey))
	r.POST("/submit", func(c *gin.Context) {
		r.ParseForm()
		name := r.FormValue("name")
		saveUser(name)
	})
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-010")
}

// ==========================================================================
// GTSS-GO-011: Hardcoded JWT Secret
// ==========================================================================

func TestGO011_JWT_HardcodedSigningKey(t *testing.T) {
	content := `package main

import "github.com/golang-jwt/jwt/v5"

func createToken(userID int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
	})
	return token.SignedString([]byte("my-super-secret-key"))
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-011")
}

func TestGO011_JWT_HardcodedVariable(t *testing.T) {
	content := `package main

var jwtSecret = "my-super-secret-key-that-should-not-be-here"

func createToken() {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-011")
}

func TestGO011_JWT_EnvVar_Safe(t *testing.T) {
	content := `package main

import (
	"os"
	"github.com/golang-jwt/jwt/v5"
)

func createToken(userID int) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
	})
	return token.SignedString([]byte(secret))
}`
	result := testutil.ScanContent(t, "/app/auth.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-011")
}

// ==========================================================================
// GTSS-GO-012: Permissive file mode
// ==========================================================================

func TestGO012_MkdirAll_0777(t *testing.T) {
	content := `package main

import "os"

func setup() {
	os.MkdirAll("/var/data/uploads", 0777)
}`
	result := testutil.ScanContent(t, "/app/setup.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-012")
}

func TestGO012_WriteFile_0777(t *testing.T) {
	content := `package main

import "os"

func save(data []byte) {
	os.WriteFile("/tmp/data.txt", data, 0777)
}`
	result := testutil.ScanContent(t, "/app/save.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-012")
}

func TestGO012_MkdirAll_0750_Safe(t *testing.T) {
	content := `package main

import "os"

func setup() {
	os.MkdirAll("/var/data/uploads", 0750)
}`
	result := testutil.ScanContent(t, "/app/setup.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-012")
}

// ==========================================================================
// GTSS-GO-013: Trusted proxy misconfiguration
// ==========================================================================

func TestGO013_GinTrustAllProxies(t *testing.T) {
	content := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.SetTrustedProxies(nil)
	r.GET("/", handler)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-013")
}

func TestGO013_EchoIPFromXFF(t *testing.T) {
	content := `package main

import "github.com/labstack/echo/v4"

func main() {
	e := echo.New()
	e.IPExtractor = echo.ExtractIPFromXFFHeader()
	e.GET("/", handler)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-013")
}

func TestGO013_GinTrustedProxies_Explicit_Safe(t *testing.T) {
	content := `package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.SetTrustedProxies([]string{"10.0.0.0/8"})
	r.GET("/", handler)
}`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-013")
}

// ==========================================================================
// GTSS-GO-014: Unsafe HTTP response
// ==========================================================================

func TestGO014_WriteUserInput_NoContentType(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Write([]byte(r.URL.Query().Get("name")))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-014")
}

func TestGO014_FprintfUserInput_NoContentType(t *testing.T) {
	content := `package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, r.FormValue("input"))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "GTSS-GO-014")
}

func TestGO014_WriteUserInput_WithContentType_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(r.URL.Query().Get("name")))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-014")
}

func TestGO014_StaticResponse_Safe(t *testing.T) {
	content := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, World!"))
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "GTSS-GO-014")
}
