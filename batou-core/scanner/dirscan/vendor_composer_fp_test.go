package dirscan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	// Pull in the PHP rule + traversal categories, the PHP AST analyzer, and
	// the taint catalog so a real PHP file-read / path-traversal flow fires in
	// the scan below. Without these the scanner emits nothing and the test
	// can't tell "tightened" from "never detected".
	_ "github.com/turenlabs/batou-core/analyzer/phpast"
	_ "github.com/turenlabs/batou-core/scanner"
	_ "github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	_ "github.com/turenlabs/batou-core/taintrule"
	_ "github.com/turenlabs/batou-rules/rules/generic"
	_ "github.com/turenlabs/batou-rules/rules/php"
	_ "github.com/turenlabs/batou-rules/rules/traversal"
)

// classLoaderBody is a faithful slice of Composer's generated
// vendor autoloader (Composer\Autoload\ClassLoader). The patterns here —
// file_exists($file = $dir . $relPath), include $file, require $vendorDir .
// '/composer/installed.php' — are exactly what fired BATOU-TAINT-file_read,
// BATOU-TRV-002, BATOU-PHPAST-003, and BATOU-GEN-019 on the real Nextcloud
// tree (apps/*/composer/composer/ClassLoader.php, 165 findings; plus
// InstalledVersions.php, 33). They are Composer-internal path arithmetic over
// the autoloader's own include map, never the app's request surface.
const classLoaderBody = `<?php

namespace Composer\Autoload;

class ClassLoader
{
    private $prefixDirsPsr4 = array();

    public function findFile($class)
    {
        $logicalPathPsr4 = strtr($class, '\\', DIRECTORY_SEPARATOR) . '.php';
        foreach ($this->prefixDirsPsr4 as $dir) {
            if (file_exists($file = $dir . DIRECTORY_SEPARATOR . $logicalPathPsr4)) {
                return $file;
            }
        }
        return false;
    }

    public function loadClass($class)
    {
        if ($file = $this->findFile($class)) {
            include $file;
            return true;
        }
        return null;
    }
}
`

// scanOneFile runs the dirscan over a directory containing a single file at the
// given relative path (with the vendor-classifier-relevant directory structure
// preserved) and returns the decoded JSONL records for that file. --with-regex
// is on so every layer that fired on the real tree fires here too.
func scanOneFileRel(t *testing.T, relPath, body string) []map[string]interface{} {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err := Run(context.Background(), Options{
		Root:         dir,
		Exts:         []string{".php"},
		Out:          &buf,
		ErrOut:       io.Discard,
		IncludeRegex: true,
		NoCallgraph:  true,
	})
	if err != nil {
		t.Fatalf("Run(%s): %v", relPath, err)
	}
	var recs []map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(buf.String()))
	for {
		var rec map[string]interface{}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		recs = append(recs, rec)
	}
	return recs
}

// The real-world FP shape: Composer's generated ClassLoader.php under a
// doubled composer/composer/ segment must scan COMPLETELY CLEAN — the file is
// reclassified as a vendored library and skipped by the scanner. This is the
// regression guard for the Nextcloud smoke-test FP class (apps/*/composer/
// composer/ClassLoader.php scanned as app code).
func TestScan_ComposerVendoredAutoloader_NoFindings(t *testing.T) {
	recs := scanOneFileRel(t,
		"apps/encryption/composer/composer/ClassLoader.php", classLoaderBody)
	if len(recs) != 0 {
		t.Fatalf("expected ZERO findings on vendored Composer ClassLoader.php "+
			"(it must be skipped as a vendored library); got %d:\n%v", len(recs), recs)
	}
}

// Tightened, not disabled: the SAME PHP body under a normal application path
// (NOT under composer/composer/) must STILL produce findings. If this goes to
// zero, the classifier change has over-reached and is hiding real app code.
func TestScan_SamePHPBodyUnderAppPath_StillFires(t *testing.T) {
	recs := scanOneFileRel(t, "apps/encryption/lib/Autoloader.php", classLoaderBody)
	if len(recs) == 0 {
		t.Fatalf("expected the Composer-shaped PHP body to STILL fire under a " +
			"normal app path (proves the vendor reclassification did not disable " +
			"PHP file-read/traversal detection); got 0 findings")
	}
	// Every finding must point at the app-path file, and none may be tagged
	// is_generated_or_vendor (the doubled composer/composer/ segment is absent).
	for _, r := range recs {
		if v, _ := r["is_generated_or_vendor"].(bool); v {
			t.Errorf("app-path finding wrongly tagged is_generated_or_vendor=true: %v", r)
		}
	}
}
