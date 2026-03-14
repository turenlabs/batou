package memory

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-MEM-014: sprintf Buffer Overflow ---

func TestMEM014_Vulnerable(t *testing.T) {
	content := `#include <stdio.h>
void format_msg(const char *name) {
    char buf[64];
    sprintf(buf, "Hello %s, welcome!", name);
    puts(buf);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-014")
}

func TestMEM014_Safe_Snprintf(t *testing.T) {
	content := `#include <stdio.h>
void format_msg(const char *name) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Hello %s, welcome!", name);
    puts(buf);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-014")
}

func TestMEM014_Safe_SnprintfOnSameLine(t *testing.T) {
	// If snprintf appears on the same line, MEM-014 should NOT fire
	content := `#include <stdio.h>
void example() {
    // prefer snprintf over sprintf(buf, fmt, ...)
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-014")
}

// --- BATOU-MEM-015: gets() Banned Function ---

func TestMEM015_Vulnerable(t *testing.T) {
	content := `#include <stdio.h>
int main() {
    char input[256];
    gets(input);
    return 0;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-015")
}

func TestMEM015_Safe_Fgets(t *testing.T) {
	content := `#include <stdio.h>
int main() {
    char input[256];
    fgets(input, sizeof(input), stdin);
    return 0;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-015")
}

// --- BATOU-MEM-016: Integer Overflow Before malloc ---

func TestMEM016_Vulnerable(t *testing.T) {
	content := `#include <stdlib.h>
void alloc_items(size_t count) {
    int *arr = malloc(count * sizeof(int));
    if (!arr) return;
    arr[0] = 42;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-016")
}

func TestMEM016_Safe_Calloc(t *testing.T) {
	content := `#include <stdlib.h>
void alloc_items(size_t count) {
    int *arr = calloc(count, sizeof(int));
    if (!arr) return;
    arr[0] = 42;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-016")
}

func TestMEM016_Safe_ConstantSize(t *testing.T) {
	content := `#include <stdlib.h>
void alloc_fixed() {
    int *arr = malloc(sizeof(int));
    free(arr);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-016")
}

// --- BATOU-MEM-017: Format String Vulnerability ---

func TestMEM017_Vulnerable_Printf(t *testing.T) {
	content := `#include <stdio.h>
void log_message(const char *msg) {
    printf(msg);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-017")
}

func TestMEM017_Vulnerable_Fprintf(t *testing.T) {
	content := `#include <stdio.h>
void log_error(FILE *fp, const char *msg) {
    fprintf(fp, msg);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-017")
}

func TestMEM017_Safe_LiteralFormat(t *testing.T) {
	content := `#include <stdio.h>
void log_message(const char *msg) {
    printf("%s", msg);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-017")
}

func TestMEM017_Safe_FprintfLiteral(t *testing.T) {
	content := `#include <stdio.h>
void log_error(FILE *fp, const char *msg) {
    fprintf(fp, "%s\n", msg);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-017")
}

// --- BATOU-MEM-018: system()/popen() with Variable ---

func TestMEM018_Vulnerable_System(t *testing.T) {
	content := `#include <stdlib.h>
void run_cmd(const char *cmd) {
    system(cmd);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-018")
}

func TestMEM018_Vulnerable_Popen(t *testing.T) {
	content := `#include <stdio.h>
FILE *run_pipe(const char *cmd) {
    return popen(cmd, "r");
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-018")
}

func TestMEM018_Safe_LiteralString(t *testing.T) {
	content := `#include <stdlib.h>
void list_files() {
    system("ls -la /tmp");
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-018")
}

// --- BATOU-MEM-019: strncpy Without Null Termination ---

func TestMEM019_Vulnerable(t *testing.T) {
	content := `#include <string.h>
void copy_name(char *dest, const char *src) {
    strncpy(dest, src, 64);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-019")
}

func TestMEM019_Safe_Strlcpy(t *testing.T) {
	content := `#include <string.h>
void copy_name(char *dest, const char *src) {
    strlcpy(dest, src, 64);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-019")
}

// --- BATOU-MEM-020: Use-After-Free realloc ---

func TestMEM020_Vulnerable(t *testing.T) {
	content := `#include <stdlib.h>
void grow_buffer(char **bufp, size_t new_size) {
    char *buf = *bufp;
    buf = realloc(buf, new_size);
    *bufp = buf;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-020")
}

func TestMEM020_Safe_TempPointer(t *testing.T) {
	content := `#include <stdlib.h>
void grow_buffer(char **bufp, size_t new_size) {
    char *tmp = realloc(*bufp, new_size);
    if (tmp) {
        *bufp = tmp;
    }
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-020")
}

func TestMEM020_Safe_DifferentVar(t *testing.T) {
	content := `#include <stdlib.h>
void grow(char *old_buf, size_t sz) {
    char *new_buf = realloc(old_buf, sz);
    if (!new_buf) { free(old_buf); return; }
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-020")
}

// --- BATOU-MEM-021: OpenSSL Deprecated API ---

func TestMEM021_Vulnerable_SSLv23(t *testing.T) {
	content := `#include <openssl/ssl.h>
void init_ssl() {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-021")
}

func TestMEM021_Vulnerable_TLSv1(t *testing.T) {
	content := `#include <openssl/ssl.h>
void init_ssl() {
    const SSL_METHOD *meth = TLSv1_method();
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-021")
}

func TestMEM021_Vulnerable_SSLLibraryInit(t *testing.T) {
	content := `#include <openssl/ssl.h>
void init() {
    SSL_library_init();
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-021")
}

func TestMEM021_Safe_TLSMethod(t *testing.T) {
	content := `#include <openssl/ssl.h>
void init_ssl() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-021")
}

// --- BATOU-MEM-022: Container Namespace Breakout ---

func TestMEM022_Vulnerable_Setns(t *testing.T) {
	content := `#include <sched.h>
void join_namespace(int fd) {
    setns(fd, CLONE_NEWPID);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-022")
}

func TestMEM022_Vulnerable_Unshare(t *testing.T) {
	content := `#include <sched.h>
void create_namespace() {
    unshare(CLONE_NEWNS | CLONE_NEWNET);
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-022")
}

func TestMEM022_Safe_NoCloneFlags(t *testing.T) {
	content := `#include <unistd.h>
void do_fork() {
    pid_t pid = fork();
    if (pid == 0) { _exit(0); }
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-022")
}

// --- BATOU-MEM-023: Deprecated RSA Key Size ---

func TestMEM023_Vulnerable_1024(t *testing.T) {
	content := `#include <openssl/rsa.h>
RSA *generate_key() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, bn, NULL);
    return rsa;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-023")
}

func TestMEM023_Vulnerable_512(t *testing.T) {
	content := `#include <openssl/rsa.h>
RSA *weak_key() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 512, bn, NULL);
    return rsa;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustFindRule(t, result, "BATOU-MEM-023")
}

func TestMEM023_Safe_2048(t *testing.T) {
	content := `#include <openssl/rsa.h>
RSA *generate_key() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);
    return rsa;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-023")
}

func TestMEM023_Safe_4096(t *testing.T) {
	content := `#include <openssl/rsa.h>
RSA *generate_key() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 4096, bn, NULL);
    return rsa;
}`
	result := testutil.ScanContent(t, "/app/handler.c", content)
	testutil.MustNotFindRule(t, result, "BATOU-MEM-023")
}
