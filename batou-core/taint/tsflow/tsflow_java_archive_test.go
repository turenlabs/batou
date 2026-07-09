package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Zip Slip: java.util.zip.ZipInputStream (CWE-22) ---
//
// Classic Zip Slip: entry name from an untrusted archive flows unchecked
// into a file-write path. Snyk's 2018 disclosure covered many Java libs
// using this pattern (CVE-2018-1000544 et al.).

func TestJava_ZipSlip_ZipInputStream(t *testing.T) {
	code := `
import java.io.*;
import java.util.zip.*;

public class Extractor {
    public void extract(InputStream in) throws Exception {
        ZipInputStream zis = new ZipInputStream(in);
        ZipEntry entry = zis.getNextEntry();
        String name = entry.getName();
        FileOutputStream fos = new FileOutputStream(name);
        fos.close();
    }
}
`
	flows := Analyze(code, "/app/Extractor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: ZipInputStream.getNextEntry() -> entry.getName() -> FileOutputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Zip Slip: java.util.jar.JarInputStream (CWE-22) ---

func TestJava_ZipSlip_JarInputStream(t *testing.T) {
	code := `
import java.io.*;
import java.util.jar.*;

public class JarExtractor {
    public void extract(InputStream in) throws Exception {
        JarInputStream jis = new JarInputStream(in);
        JarEntry entry = jis.getNextJarEntry();
        String name = entry.getName();
        FileOutputStream fos = new FileOutputStream(name);
        fos.close();
    }
}
`
	flows := Analyze(code, "/app/JarExtractor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: JarInputStream.getNextJarEntry() -> entry.getName() -> FileOutputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Zip Slip: Apache Commons Compress ZipArchiveInputStream (CWE-22) ---

func TestJava_ZipSlip_CommonsCompressZip(t *testing.T) {
	code := `
import java.io.*;
import org.apache.commons.compress.archivers.zip.*;

public class CompressExtractor {
    public void extract(InputStream in) throws Exception {
        ZipArchiveInputStream zis = new ZipArchiveInputStream(in);
        ZipArchiveEntry entry = zis.getNextZipEntry();
        String name = entry.getName();
        FileWriter fw = new FileWriter(name);
        fw.close();
    }
}
`
	flows := Analyze(code, "/app/CompressExtractor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow: ZipArchiveInputStream.getNextZipEntry() -> entry.getName() -> FileWriter")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Tar Slip: Apache Commons Compress TarArchiveInputStream (CWE-22) ---

func TestJava_TarSlip_CommonsCompressTar(t *testing.T) {
	code := `
import java.io.*;
import org.apache.commons.compress.archivers.tar.*;

public class TarExtractor {
    public void extract(InputStream in) throws Exception {
        TarArchiveInputStream tis = new TarArchiveInputStream(in);
        TarArchiveEntry entry = tis.getNextTarEntry();
        String name = entry.getName();
        FileOutputStream fos = new FileOutputStream(name);
        fos.close();
    }
}
`
	flows := Analyze(code, "/app/TarExtractor.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Tar Slip flow: TarArchiveInputStream.getNextTarEntry() -> entry.getName() -> FileOutputStream")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// --- Safe: filename-only extraction strips directory components (no flow expected) ---

func TestJava_ZipSlip_Safe_FilenameUtilsGetName(t *testing.T) {
	code := `
import java.io.*;
import java.util.zip.*;
import org.apache.commons.io.FilenameUtils;

public class SafeExtractor {
    public void extract(InputStream in) throws Exception {
        ZipInputStream zis = new ZipInputStream(in);
        ZipEntry entry = zis.getNextEntry();
        String name = entry.getName();
        String safe = FilenameUtils.getName(name);
        FileOutputStream fos = new FileOutputStream(safe);
        fos.close();
    }
}
`
	flows := Analyze(code, "/app/SafeExtractor.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected NO Zip Slip flow when path is sanitized via FilenameUtils.getName()")
	}
}
