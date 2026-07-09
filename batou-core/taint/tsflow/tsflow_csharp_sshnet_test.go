package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# Renci.SshNet (SSH.NET) — remote command injection + SFTP/SCP path
// traversal. SSH.NET is the dominant .NET SSH library; tainted input into
// SshClient.RunCommand / CreateCommand is RCE on the remote host, and tainted
// input into SftpClient / ScpClient path arguments is path traversal on the
// remote filesystem.
// ===========================================================================

// --- SSH command injection ---

func TestCSharp_Sink_SSHNet_RunCommand(t *testing.T) {
	code := `
using System;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class RemoteController : Controller {
    private readonly SshClient client;
    public IActionResult Run() {
        string target = Request.QueryString.Value;
        var cmd = client.RunCommand(target);
        return Ok(cmd.Result);
    }
}
`
	flows := Analyze(code, "/app/RemoteController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for Request.QueryString -> SshClient.RunCommand (remote RCE)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_SSHNet_CreateCommand(t *testing.T) {
	code := `
using System;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class RemoteController : Controller {
    private readonly SshClient client;
    public IActionResult Run() {
        string script = Request.QueryString.Value;
        var cmd = client.CreateCommand(script);
        cmd.Execute();
        return Ok(cmd.Result);
    }
}
`
	flows := Analyze(code, "/app/RemoteController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for Request.QueryString -> SshClient.CreateCommand (remote RCE via Execute())")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SFTP path traversal: reads ---

func TestCSharp_Sink_SSHNet_Sftp_ReadAllText(t *testing.T) {
	code := `
using System;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller {
    private readonly SftpClient sftp;
    public IActionResult Get() {
        string path = Request.Path;
        string body = sftp.ReadAllText(path);
        return Content(body);
    }
}
`
	flows := Analyze(code, "/app/FileController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for Request.Path -> SftpClient.ReadAllText (remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_SSHNet_Sftp_OpenRead(t *testing.T) {
	code := `
using System;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller {
    private readonly SftpClient sftp;
    public IActionResult Get() {
        string path = Request.Path;
        var stream = sftp.OpenRead(path);
        return File(stream, "application/octet-stream");
    }
}
`
	flows := Analyze(code, "/app/FileController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for Request.Path -> SftpClient.OpenRead (remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_SSHNet_Sftp_DownloadFile(t *testing.T) {
	code := `
using System;
using System.IO;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller {
    private readonly SftpClient sftp;
    public IActionResult Get(Stream output) {
        string remote = Request.QueryString.Value;
        sftp.DownloadFile(remote, output);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/FileController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for Request.QueryString -> SftpClient.DownloadFile (remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SFTP path traversal: writes ---

func TestCSharp_Sink_SSHNet_Sftp_WriteAllText(t *testing.T) {
	code := `
using System;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller {
    private readonly SftpClient sftp;
    public IActionResult Put() {
        string path = Request.QueryString.Value;
        sftp.WriteAllText(path, "payload");
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/FileController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for Request.QueryString -> SftpClient.WriteAllText (remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_SSHNet_Sftp_UploadFile(t *testing.T) {
	code := `
using System;
using System.IO;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller {
    private readonly SftpClient sftp;
    public IActionResult Upload(Stream body) {
        string remote = Request.QueryString.Value;
        sftp.UploadFile(body, remote);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/FileController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for Request.QueryString -> SftpClient.UploadFile (remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_SSHNet_Sftp_DeleteFile(t *testing.T) {
	code := `
using System;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller {
    private readonly SftpClient sftp;
    public IActionResult Delete() {
        string path = Request.Path;
        sftp.DeleteFile(path);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/FileController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for Request.Path -> SftpClient.DeleteFile (destructive remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- SCP path traversal ---

func TestCSharp_Sink_SSHNet_Scp_Upload(t *testing.T) {
	code := `
using System;
using System.IO;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class ScpController : Controller {
    private readonly ScpClient scp;
    public IActionResult Send(FileInfo local) {
        string remote = Request.QueryString.Value;
        scp.Upload(local, remote);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ScpController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected SnkFileWrite flow for Request.QueryString -> ScpClient.Upload (remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_SSHNet_Scp_Download(t *testing.T) {
	code := `
using System;
using System.IO;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class ScpController : Controller {
    private readonly ScpClient scp;
    public IActionResult Get(FileInfo local) {
        string remote = Request.QueryString.Value;
        scp.Download(remote, local);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ScpController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected SnkFileRead flow for Request.QueryString -> ScpClient.Download (remote path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Safe cases ---

// Safe: command text is a literal; only a benign unused variable is tainted.
// Must not fire SnkCommand.
func TestCSharp_Sink_SSHNet_RunCommand_Safe_Literal(t *testing.T) {
	code := `
using System;
using Renci.SshNet;
using Microsoft.AspNetCore.Mvc;

public class RemoteController : Controller {
    private readonly SshClient client;
    public IActionResult Run() {
        string unrelated = Request.QueryString.Value;
        var cmd = client.RunCommand("uptime");
        return Ok(cmd.Result);
    }
}
`
	flows := Analyze(code, "/app/RemoteController.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("did not expect SnkCommand flow when command text is a literal; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
