package framework

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-009: Express res.redirect with user input
// ---------------------------------------------------------------------------

func TestExpress009_RedirectReqQuery(t *testing.T) {
	content := `app.get('/login/callback', (req, res) => {
  res.redirect(req.query.returnUrl);
});`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-FW-EXPRESS-009")
}

func TestExpress009_RedirectReqBody(t *testing.T) {
	content := `app.post('/auth', (req, res) => {
  res.redirect(req.body.redirect);
});`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-FW-EXPRESS-009")
}

func TestExpress009_RedirectReqParams(t *testing.T) {
	content := `app.get('/goto/:url', (req, res) => {
  res.redirect(req.params.url);
});`
	result := testutil.ScanContent(t, "/app/redirect.js", content)
	testutil.MustFindRule(t, result, "BATOU-FW-EXPRESS-009")
}

func TestExpress009_RedirectReqQueryBracket(t *testing.T) {
	content := `app.get('/callback', (req, res) => {
  res.redirect(req.query['next']);
});`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustFindRule(t, result, "BATOU-FW-EXPRESS-009")
}

func TestExpress009_WithValidation_Safe(t *testing.T) {
	content := `app.get('/login/callback', (req, res) => {
  const url = req.query.returnUrl;
  if (isValidRedirect(url)) {
    res.redirect(req.query.returnUrl);
  } else {
    res.redirect('/');
  }
});`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-EXPRESS-009")
}

func TestExpress009_WithAllowlist_Safe(t *testing.T) {
	content := `app.get('/callback', (req, res) => {
  const url = req.query.next;
  const allowed = allowlist.includes(url);
  if (allowed) {
    res.redirect(req.query.next);
  }
});`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-EXPRESS-009")
}

func TestExpress009_StaticRedirect_Safe(t *testing.T) {
	content := `app.get('/old-page', (req, res) => {
  res.redirect('/new-page');
});`
	result := testutil.ScanContent(t, "/app/routes.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-EXPRESS-009")
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-009: Next.js getServerSideProps SQL injection
// ---------------------------------------------------------------------------

func TestNextJS009_GSSPQueryToSQL(t *testing.T) {
	content := `export async function getServerSideProps(context) {
  const { id } = context.query;
  const result = await db.query(` + "`SELECT * FROM posts WHERE id = ${id}`" + `);
  return { props: { post: result } };
}`
	result := testutil.ScanContent(t, "/app/pages/post.tsx", content)
	// NESTJS-003 also matches .query(`...${}`), dedup keeps one by rule ID order
	testutil.MustFindAnyRule(t, result, "BATOU-FW-NEXTJS-009", "BATOU-FW-NESTJS-003")
}

func TestNextJS009_GSSPParamsConcat(t *testing.T) {
	content := `export async function getServerSideProps(context) {
  const slug = context.params.slug;
  const result = await db.query("SELECT * FROM pages WHERE slug = '" + slug + "'");
  return { props: { page: result } };
}`
	result := testutil.ScanContent(t, "/app/pages/[slug].tsx", content)
	// NESTJS-003 may also match .query("..." +), dedup keeps one
	testutil.MustFindAnyRule(t, result, "BATOU-FW-NEXTJS-009", "BATOU-FW-NESTJS-003")
}

func TestNextJS009_Parameterized_Safe(t *testing.T) {
	content := `export async function getServerSideProps(context) {
  const { id } = context.query;
  const safeId = parseInt(id);
  const result = await db.query('SELECT * FROM posts WHERE id = $1', [safeId]);
  return { props: { post: result } };
}`
	result := testutil.ScanContent(t, "/app/pages/post.tsx", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-NEXTJS-009")
}

func TestNextJS009_WithValidation_Safe(t *testing.T) {
	content := `import { z } from 'zod';
export async function getServerSideProps(context) {
  const schema = z.object({ id: z.string().uuid() });
  const { id } = schema.parse(context.query);
  const post = await prisma.post.findUnique({ where: { id } });
  return { props: { post } };
}`
	result := testutil.ScanContent(t, "/app/pages/post.tsx", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-NEXTJS-009")
}

func TestNextJS009_NoQueryAccess_Safe(t *testing.T) {
	content := `export async function getServerSideProps() {
  const posts = await db.query('SELECT * FROM posts ORDER BY created_at DESC LIMIT 10');
  return { props: { posts } };
}`
	result := testutil.ScanContent(t, "/app/pages/index.tsx", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-NEXTJS-009")
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-011: FastAPI unvalidated parameters
// ---------------------------------------------------------------------------

func TestFastAPI011_PlainStrParam(t *testing.T) {
	content := `from fastapi import FastAPI
app = FastAPI()

@app.get("/search")
def search(query: str):
    return {"results": do_search(query)}`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FASTAPI-011")
}

func TestFastAPI011_PlainIDParam(t *testing.T) {
	content := `from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
def get_user(user_id):
    return db.get(user_id)`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustFindRule(t, result, "BATOU-FW-FASTAPI-011")
}

func TestFastAPI011_WithQueryValidator_Safe(t *testing.T) {
	content := `from fastapi import FastAPI, Query
app = FastAPI()

@app.get("/search")
def search(query: str = Query(..., min_length=1, max_length=100)):
    return {"results": do_search(query)}`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FASTAPI-011")
}

func TestFastAPI011_WithPathValidator_Safe(t *testing.T) {
	content := `from fastapi import FastAPI, Path, Depends
app = FastAPI()

@app.get("/users/{user_id}")
def get_user(user_id: int = Path(..., gt=0)):
    return db.get(user_id)`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FASTAPI-011")
}

func TestFastAPI011_WithDepends_Safe(t *testing.T) {
	content := `from fastapi import FastAPI, Depends
app = FastAPI()

@app.get("/items")
def get_items(params = Depends(get_query_params)):
    return db.search(params)`
	result := testutil.ScanContent(t, "/app/main.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-FASTAPI-011")
}

// ---------------------------------------------------------------------------
// BATOU-FW-GIN-011: Gin db.Raw/db.Exec with fmt.Sprintf
// ---------------------------------------------------------------------------

func TestGin011_RawSprintf(t *testing.T) {
	content := `package main
import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	name := c.Query("name")
	db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)).Scan(&users)
	c.JSON(200, users)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-FW-GIN-011")
}

func TestGin011_ExecSprintf(t *testing.T) {
	content := `package main
import "github.com/gin-gonic/gin"

func deleteHandler(c *gin.Context) {
	id := c.Param("id")
	db.Exec(fmt.Sprintf("DELETE FROM records WHERE id = %s", id))
	c.Status(204)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-FW-GIN-011")
}

func TestGin011_RawConcat(t *testing.T) {
	content := `package main
import "github.com/gin-gonic/gin"

func searchHandler(c *gin.Context) {
	q := c.Query("q")
	db.Raw("SELECT * FROM items WHERE name LIKE '%" + q + "%'").Scan(&items)
	c.JSON(200, items)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-FW-GIN-011")
}

func TestGin011_Parameterized_Safe(t *testing.T) {
	content := `package main
import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	name := c.Query("name")
	db.Raw("SELECT * FROM users WHERE name = ?", name).Scan(&users)
	c.JSON(200, users)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-GIN-011")
}

func TestGin011_GORMWhere_Safe(t *testing.T) {
	content := `package main
import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	name := c.Query("name")
	db.Where("name = ?", name).Find(&users)
	c.JSON(200, users)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-GIN-011")
}

func TestGin011_NonGinFile_Safe(t *testing.T) {
	content := `package main

func process() {
	db.Raw(fmt.Sprintf("SELECT * FROM logs WHERE date = '%s'", date))
}`
	result := testutil.ScanContent(t, "/app/process.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-GIN-011")
}
