package framework

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// --- BATOU-FW-VUE-001: v-html with user data ---

func TestVue001_VHtmlUserData(t *testing.T) {
	content := `<template>
  <div v-html="userComment"></div>
</template>
<script>
export default { props: ['userComment'] }
</script>`
	result := testutil.ScanContent(t, "/app/components/Comment.vue", content)
	testutil.MustFindRule(t, result, "BATOU-FW-VUE-001")
}

func TestVue001_VHtmlRawMarkdown(t *testing.T) {
	content := `<template>
  <article v-html="renderedMarkdown"></article>
</template>`
	result := testutil.ScanContent(t, "/app/components/Article.vue", content)
	testutil.MustFindRule(t, result, "BATOU-FW-VUE-001")
}

func TestVue001_VHtmlConstant_Safe(t *testing.T) {
	// Bound to a static, non-user-looking value — must not flag.
	content := `<template>
  <div v-html="staticFooterDoc"></div>
  <span>{{ title }}</span>
</template>`
	result := testutil.ScanContent(t, "/app/components/Footer.vue", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-VUE-001")
}

// --- BATOU-FW-VUE-002: Vue.compile of user input ---

func TestVue002_CompileTemplateLiteral(t *testing.T) {
	content := "const render = Vue.compile(`<div>${userInput}</div>`);"
	result := testutil.ScanContent(t, "/app/dyn.js", content)
	testutil.MustFindRule(t, result, "BATOU-FW-VUE-002")
}

func TestVue002_CompileUserVar(t *testing.T) {
	content := `const tpl = req.body.template;
const fn = Vue.compile(userTemplate);`
	result := testutil.ScanContent(t, "/app/dyn2.js", content)
	testutil.MustFindRule(t, result, "BATOU-FW-VUE-002")
}

func TestVue002_CompileConstant_Safe(t *testing.T) {
	content := `const render = Vue.compile('<p>Hello world</p>');`
	result := testutil.ScanContent(t, "/app/static.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-VUE-002")
}

// --- BATOU-FW-VUE-003: render-function innerHTML via domProps ---

func TestVue003_RenderInnerHTMLUserData(t *testing.T) {
	content := `render(h) {
  return h('div', { domProps: { innerHTML: this.userContent } });
}`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "BATOU-FW-VUE-003")
}

func TestVue003_RenderInnerHTMLConstant_Safe(t *testing.T) {
	content := `render(h) {
  return h('div', { domProps: { innerHTML: STATIC_BANNER } });
}`
	result := testutil.ScanContent(t, "/app/render_safe.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-VUE-003")
}
