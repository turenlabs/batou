package tsflow

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// JSch ChannelSftp remote file-op sinks (CWE-22 path traversal, CWE-918 SSRF).
//
// Java's catalog previously had only `java.jsch.channelexec.setcommand` for SSH.
// The JSch SFTP subsystem (`ChannelSftp`) — the dominant Java SFTP client used by
// Maven, Gradle, Jenkins, Ant, Spring Integration, Apache Camel, and most Java
// deployment tools — exposed put/get/mkdir/rmdir/rm/rename/symlink/hardlink/
// chmod/chown/chgrp/ls/stat/realpath without modelling. Coupled with `JSch.getSession`
// SSRF (attacker-chosen SSH target host), this rounds out SSH parity matching
// the Ruby/PHP/Rust waves landed in cycles #885-#887.
//
// Receiver-binding: ObjectType "ChannelSftp" binds receivers `channelSftp`
// (lower==lastPart "channelsftp") and `channel` (HasPrefix("channelsftp",
// "channel")=true) via tsflow matcher heuristics. The shorter canonical
// receiver `sftp` does NOT bind via lastPart (HasPrefix("channelsftp","sftp")
// is false) — those uses hit Layer 1 regex fallback only. All positive tests
// below use receivers `channelSftp` or `channel` to exercise the tsflow path.
//
// Source pattern: explicit `request.getParameter("path")` (java.servlet.getparameter).
// Avoids the cycle #759 web-handler auto-taint trigger (no executeQuery/Query(/
// Path(/Json(/Form( substrings in the fixtures).

// --- put(src, dst) — local→remote upload, both args path-controlled ---

func TestJava_JSch_ChannelSftp_Put_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class Uploader {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String remote = request.getParameter("dest");
        channelSftp.put("/tmp/local.bin", remote);
    }
}
`
	flows := Analyze(code, "/app/Uploader.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.put")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- get(src, dst) — remote→local download, remote path tainted ---

func TestJava_JSch_ChannelSftp_Get_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class Downloader {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String remote = request.getParameter("src");
        channelSftp.get(remote, "/tmp/out.bin");
    }
}
`
	flows := Analyze(code, "/app/Downloader.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- mkdir(path) ---

func TestJava_JSch_ChannelSftp_Mkdir_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class DirMaker {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String dir = request.getParameter("dir");
        channelSftp.mkdir(dir);
    }
}
`
	flows := Analyze(code, "/app/DirMaker.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.mkdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- rmdir(path) ---

func TestJava_JSch_ChannelSftp_Rmdir_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class DirRemover {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String dir = request.getParameter("dir");
        channelSftp.rmdir(dir);
    }
}
`
	flows := Analyze(code, "/app/DirRemover.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.rmdir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- rm(path) ---

func TestJava_JSch_ChannelSftp_Rm_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class FileRemover {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String victim = request.getParameter("target");
        channelSftp.rm(victim);
    }
}
`
	flows := Analyze(code, "/app/FileRemover.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.rm")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- rename(oldpath, newpath) — both args tainted via second-source variation ---

func TestJava_JSch_ChannelSftp_Rename_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class Renamer {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String dst = request.getParameter("dst");
        channelSftp.rename("/srv/old", dst);
    }
}
`
	flows := Analyze(code, "/app/Renamer.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.rename")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- symlink(target, linkpath) ---

func TestJava_JSch_ChannelSftp_Symlink_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class Linker {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String tgt = request.getParameter("target");
        channelSftp.symlink(tgt, "/srv/shortcut");
    }
}
`
	flows := Analyze(code, "/app/Linker.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.symlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- hardlink(oldpath, newpath) — Mwiede fork extension ---

func TestJava_JSch_ChannelSftp_Hardlink_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class HardLinker {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String tgt = request.getParameter("target");
        channelSftp.hardlink(tgt, "/srv/alias");
    }
}
`
	flows := Analyze(code, "/app/HardLinker.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.hardlink")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- chmod(permissions, path) — path at index 1 ---

func TestJava_JSch_ChannelSftp_Chmod_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class PermChanger {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String victim = request.getParameter("file");
        channelSftp.chmod(0644, victim);
    }
}
`
	flows := Analyze(code, "/app/PermChanger.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.chmod")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- chown(uid, path) — path at index 1 ---

func TestJava_JSch_ChannelSftp_Chown_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class OwnerChanger {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String victim = request.getParameter("file");
        channelSftp.chown(1000, victim);
    }
}
`
	flows := Analyze(code, "/app/OwnerChanger.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.chown")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- chgrp(gid, path) — path at index 1 ---

func TestJava_JSch_ChannelSftp_Chgrp_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class GroupChanger {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String victim = request.getParameter("file");
        channelSftp.chgrp(100, victim);
    }
}
`
	flows := Analyze(code, "/app/GroupChanger.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for ChannelSftp.chgrp")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- ls(path) ---

func TestJava_JSch_ChannelSftp_Ls_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class DirLister {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String dir = request.getParameter("dir");
        channelSftp.ls(dir);
    }
}
`
	flows := Analyze(code, "/app/DirLister.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.ls")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- stat(path) ---

func TestJava_JSch_ChannelSftp_Stat_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class FileStat {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String target = request.getParameter("file");
        channelSftp.stat(target);
    }
}
`
	flows := Analyze(code, "/app/FileStat.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.stat")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- realpath(path) ---

func TestJava_JSch_ChannelSftp_Realpath_PathTraversal(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import javax.servlet.http.HttpServletRequest;

public class Resolver {
    private ChannelSftp channelSftp;
    public void run(HttpServletRequest request) throws Exception {
        String target = request.getParameter("file");
        channelSftp.realpath(target);
    }
}
`
	flows := Analyze(code, "/app/Resolver.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for ChannelSftp.realpath")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- JSch.getSession(user, host, port) — tainted host = SSH SSRF ---

func TestJava_JSch_GetSession_SSRF(t *testing.T) {
	code := `
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import javax.servlet.http.HttpServletRequest;

public class Connector {
    private JSch jsch;
    public void run(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        Session sess = jsch.getSession("user", host, 22);
        sess.connect();
    }
}
`
	flows := Analyze(code, "/app/Connector.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SnkURLFetch flow for JSch.getSession with tainted host")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: hardcoded paths/hosts produce no flow ---

func TestJava_JSch_ChannelSftp_NoFlow_HardcodedInputs(t *testing.T) {
	code := `
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class StaticUploader {
    private ChannelSftp channelSftp;
    private JSch jsch;
    public void run() throws Exception {
        channelSftp.put("/tmp/local.bin", "/srv/static/upload.bin");
        channelSftp.mkdir("/srv/static/cache");
        channelSftp.rm("/srv/static/old.bin");
        channelSftp.rename("/srv/static/a", "/srv/static/b");
        channelSftp.chmod(0644, "/srv/static/perm.bin");
        channelSftp.ls("/srv/static");
        Session sess = jsch.getSession("deploy", "build.internal", 22);
        sess.connect();
    }
}
`
	flows := Analyze(code, "/app/StaticUploader.java", rules.LangJava)
	for _, f := range flows {
		if strings.HasPrefix(f.Sink.ID, "java.jsch.channelsftp.") || f.Sink.ID == "java.jsch.jsch.getsession" {
			t.Errorf("unexpected flow with hardcoded inputs: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Catalog registration check ---

func TestJava_JSch_ChannelSftp_CatalogRegistered(t *testing.T) {
	want := []string{
		"java.jsch.channelsftp.put",
		"java.jsch.channelsftp.get",
		"java.jsch.channelsftp.mkdir",
		"java.jsch.channelsftp.rmdir",
		"java.jsch.channelsftp.rm",
		"java.jsch.channelsftp.rename",
		"java.jsch.channelsftp.symlink",
		"java.jsch.channelsftp.hardlink",
		"java.jsch.channelsftp.chmod",
		"java.jsch.channelsftp.chown",
		"java.jsch.channelsftp.chgrp",
		"java.jsch.channelsftp.ls",
		"java.jsch.channelsftp.stat",
		"java.jsch.channelsftp.realpath",
		"java.jsch.jsch.getsession",
	}
	catalog := taint.GetCatalog(rules.LangJava)
	if catalog == nil {
		t.Fatal("no Java taint catalog registered")
	}
	have := make(map[string]bool)
	for _, s := range catalog.Sinks() {
		have[s.ID] = true
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("missing sink registration: %s", id)
		}
	}
}
