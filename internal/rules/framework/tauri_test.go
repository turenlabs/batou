package framework

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-FW-TAURI-001: Dangerous Shell Command Allowlist
// ==========================================================================

func TestTauri001_ShellAllTrue(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "shell": {
        "all": true
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri001_ShellExecuteTrue(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "shell": {
        "execute": true
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri001_ShellAllowExecuteV2(t *testing.T) {
	content := `{
  "permissions": [
    "shell:allow-execute"
  ]
}`
	result := testutil.ScanContent(t, "/app/src-tauri/capabilities/main.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri001_RustCommandNew(t *testing.T) {
	content := `use tauri::command;

#[tauri::command]
fn run_program(cmd: String) -> Result<String, String> {
    let output = std::process::Command::new(&cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}`
	result := testutil.ScanContent(t, "/app/src-tauri/src/commands.rs", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri001_JSCommandCreate(t *testing.T) {
	content := `import { Command } from '@tauri-apps/api/shell';
const cmd = Command.create('my-sidecar', [userInput]);
const output = await cmd.execute();`
	result := testutil.ScanContent(t, "/app/src/lib/commands.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri001_JSShellInvoke(t *testing.T) {
	content := `import { invoke } from '@tauri-apps/api';
const result = await invoke("plugin:shell|execute", { program: userCmd });`
	result := testutil.ScanContent(t, "/app/src/commands.ts", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri001_Safe_ShellAllFalse(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "shell": {
        "all": false,
        "open": true
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri001_Safe_NoShellConfig(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "fs": {
        "scope": ["$APPDATA/myapp/**"]
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-001")
}

// ==========================================================================
// GTSS-FW-TAURI-002: Overly Permissive Filesystem Scope
// ==========================================================================

func TestTauri002_FsScopeHomeStar(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "fs": {
        "scope": ["$HOME/**"]
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-002")
}

func TestTauri002_FsScopeAppDataStar(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "fs": {
        "scope": ["$APPDATA/**"]
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-002")
}

func TestTauri002_FsScopeWildcard(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "fs": {
        "scope": ["**"]
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-002")
}

func TestTauri002_FsScopeRootWildcard(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "fs": {
        "scope": ["/**"]
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-002")
}

func TestTauri002_Safe_RestrictedScope(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "fs": {
        "scope": ["$APPDATA/myapp/**"]
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-002")
}

func TestTauri002_Safe_NoFsScope(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "dialog": {
        "all": true
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-002")
}

// ==========================================================================
// GTSS-FW-TAURI-003: IPC Command Injection
// ==========================================================================

func TestTauri003_RustCommandWithProcessSpawn(t *testing.T) {
	content := `use tauri::command;

#[tauri::command]
fn execute(program: String, args: Vec<String>) -> Result<String, String> {
    let output = std::process::Command::new(program)
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}`
	result := testutil.ScanContent(t, "/app/src-tauri/src/main.rs", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-003")
}

func TestTauri003_JSInvokeVariable(t *testing.T) {
	content := `import { invoke } from '@tauri-apps/api';
const commandName = getCommandFromUser();
const result = await invoke(commandName, { data: payload });`
	result := testutil.ScanContent(t, "/app/src/api.ts", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-003")
}

func TestTauri003_JSInvokeUserInput(t *testing.T) {
	content := `import { invoke } from '@tauri-apps/api';
const cmdName = document.getElementById('cmd').value;
const result = await invoke(cmdName);`
	result := testutil.ScanContent(t, "/app/src/app.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-003")
}

func TestTauri003_Safe_InvokeStringLiteral(t *testing.T) {
	content := `import { invoke } from '@tauri-apps/api';
const result = await invoke('get_data', { id: 42 });`
	result := testutil.ScanContent(t, "/app/src/api.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-003")
}

func TestTauri003_Safe_RustValidatedCommand(t *testing.T) {
	content := `use tauri::command;

#[tauri::command]
fn get_user(id: i32) -> Result<User, String> {
    let user = db::find_user(id).map_err(|e| e.to_string())?;
    Ok(user)
}`
	result := testutil.ScanContent(t, "/app/src-tauri/src/commands.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-003")
}

// ==========================================================================
// GTSS-FW-TAURI-004: Dangerous Protocol Handler
// ==========================================================================

func TestTauri004_CustomProtocolNoOrigin(t *testing.T) {
	content := `use tauri::AppHandle;

fn setup(app: &mut tauri::App) {
    app.register_uri_scheme_protocol("myapp", |_app, request| {
        let path = request.uri().path();
        let content = std::fs::read(path).unwrap();
        tauri::http::ResponseBuilder::new()
            .body(content)
    });
}`
	result := testutil.ScanContent(t, "/app/src-tauri/src/main.rs", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-004")
}

func TestTauri004_DangerousSchemeFile(t *testing.T) {
	content := `{
  "tauri": {
    "allowlist": {
      "shell": {
        "open": "file://"
      }
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-004")
}

func TestTauri004_Safe_ProtocolWithOriginCheck(t *testing.T) {
	content := `use tauri::AppHandle;

fn setup(app: &mut tauri::App) {
    app.register_uri_scheme_protocol("myapp", |_app, request| {
        let origin = request.headers().get("Origin").unwrap();
        if origin != "tauri://localhost" {
            return Err("invalid origin".into());
        }
        let content = std::fs::read("allowed_file.txt").unwrap();
        tauri::http::ResponseBuilder::new()
            .body(content)
    });
}`
	result := testutil.ScanContent(t, "/app/src-tauri/src/main.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-004")
}

// ==========================================================================
// GTSS-FW-TAURI-005: CSP Bypass or Missing CSP
// ==========================================================================

func TestTauri005_CSPUnsafeInline(t *testing.T) {
	content := `{
  "tauri": {
    "security": {
      "csp": "default-src 'self'; script-src 'unsafe-inline'"
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-005")
}

func TestTauri005_CSPUnsafeEval(t *testing.T) {
	content := `{
  "tauri": {
    "security": {
      "csp": "default-src 'self'; script-src 'unsafe-eval'"
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-005")
}

func TestTauri005_CSPWildcard(t *testing.T) {
	content := `{
  "tauri": {
    "security": {
      "csp": "default-src *"
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-005")
}

func TestTauri005_MissingCSP(t *testing.T) {
	content := `{
  "tauri": {
    "security": {}
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-005")
}

func TestTauri005_Safe_StrictCSP(t *testing.T) {
	content := `{
  "tauri": {
    "security": {
      "csp": "default-src 'self'; script-src 'self'"
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-005")
}

// ==========================================================================
// GTSS-FW-TAURI-006: window.__TAURI__ Exposure
// ==========================================================================

func TestTauri006_WithGlobalTauriTrue(t *testing.T) {
	content := `{
  "build": {
    "withGlobalTauri": true
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-006")
}

func TestTauri006_TauriAPILeakPostMessage(t *testing.T) {
	content := `import { invoke } from '@tauri-apps/api';
// Leak Tauri APIs to iframe
iframe.contentWindow.postMessage(window.__TAURI__, '*');`
	result := testutil.ScanContent(t, "/app/src/bridge.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-006")
}

func TestTauri006_TauriUnsafeContext(t *testing.T) {
	content := `import { invoke } from '@tauri-apps/api';
document.getElementById('output').innerHTML = window.__TAURI__.fs.readTextFile(path);`
	result := testutil.ScanContent(t, "/app/src/render.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-006")
}

func TestTauri006_Safe_WithGlobalTauriFalse(t *testing.T) {
	content := `{
  "build": {
    "withGlobalTauri": false
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-006")
}

func TestTauri006_Safe_ImportAPI(t *testing.T) {
	content := `import { invoke } from '@tauri-apps/api';
const data = await invoke('get_data');`
	result := testutil.ScanContent(t, "/app/src/api.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-006")
}

// ==========================================================================
// GTSS-FW-TAURI-007: Dangerous Tauri v2 Permissions
// ==========================================================================

func TestTauri007_ShellAllowExecute(t *testing.T) {
	content := `{
  "identifier": "main-capability",
  "windows": ["main"],
  "permissions": [
    "shell:allow-execute"
  ]
}`
	result := testutil.ScanContent(t, "/app/src-tauri/capabilities/main.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-007")
}

func TestTauri007_ShellAllowOpen(t *testing.T) {
	content := `{
  "identifier": "main-capability",
  "windows": ["main"],
  "permissions": [
    "shell:allow-open"
  ]
}`
	result := testutil.ScanContent(t, "/app/src-tauri/capabilities/main.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-007")
}

func TestTauri007_FsWriteNoScope(t *testing.T) {
	content := `{
  "identifier": "main-capability",
  "windows": ["main"],
  "permissions": [
    "fs:allow-write"
  ]
}`
	result := testutil.ScanContent(t, "/app/src-tauri/capabilities/main.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-007")
}

func TestTauri007_AllWindowsDangerous(t *testing.T) {
	content := `{
  "identifier": "dangerous-capability",
  "windows": ["*"],
  "permissions": [
    "shell:allow-execute",
    "fs:allow-write"
  ]
}`
	result := testutil.ScanContent(t, "/app/src-tauri/capabilities/main.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-007")
}

func TestTauri007_Safe_RestrictedPerms(t *testing.T) {
	content := `{
  "identifier": "main-capability",
  "windows": ["main"],
  "permissions": [
    "dialog:allow-open",
    "dialog:allow-save"
  ]
}`
	result := testutil.ScanContent(t, "/app/src-tauri/capabilities/main.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-007")
}

// ==========================================================================
// GTSS-FW-TAURI-008: Insecure Updater Configuration
// ==========================================================================

func TestTauri008_HTTPEndpoint(t *testing.T) {
	content := `{
  "tauri": {
    "updater": {
      "active": true,
      "endpoints": ["http://updates.example.com/{{target}}/{{current_version}}"],
      "pubkey": "dW50cnVzdGVkIGNvbW1lbnQgOiBtaW5pc2lnbiBwdWJs"
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-008")
}

func TestTauri008_NoPubkey(t *testing.T) {
	content := `{
  "tauri": {
    "updater": {
      "active": true,
      "endpoints": ["https://updates.example.com/{{target}}/{{current_version}}"]
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-008")
}

func TestTauri008_RustDangerousInsecure(t *testing.T) {
	content := `use tauri::updater::UpdateBuilder;
let update = tauri::updater::builder(app.handle())
    .dangerous_insecure_transport_protocol(true)
    .build()?;`
	result := testutil.ScanContent(t, "/app/src-tauri/src/update.rs", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-008")
}

func TestTauri008_Safe_HTTPSWithPubkey(t *testing.T) {
	content := `{
  "tauri": {
    "updater": {
      "active": true,
      "endpoints": ["https://updates.example.com/{{target}}/{{current_version}}"],
      "pubkey": "dW50cnVzdGVkIGNvbW1lbnQgOiBtaW5pc2lnbiBwdWJs"
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-008")
}

func TestTauri008_Safe_NoUpdater(t *testing.T) {
	content := `{
  "tauri": {
    "bundle": {
      "active": true
    }
  }
}`
	result := testutil.ScanContent(t, "/app/src-tauri/tauri.conf.json", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-008")
}

// ==========================================================================
// Fixture-based tests
// ==========================================================================

func TestTauri_VulnerableBackendFixture(t *testing.T) {
	content := testutil.LoadFixture(t, "rust/vulnerable/tauri_backend.rs")
	result := testutil.ScanContent(t, "/app/src-tauri/src/commands.rs", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-003")
}

func TestTauri_SafeBackendFixture(t *testing.T) {
	content := testutil.LoadFixture(t, "rust/safe/tauri_backend_safe.rs")
	result := testutil.ScanContent(t, "/app/src-tauri/src/commands.rs", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-001")
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-003")
}

func TestTauri_VulnerableFrontendFixture(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/tauri_frontend.js")
	result := testutil.ScanContent(t, "/app/src/commands.js", content)
	testutil.MustFindRule(t, result, "GTSS-FW-TAURI-001")
}

func TestTauri_SafeFrontendFixture(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/safe/tauri_frontend_safe.js")
	result := testutil.ScanContent(t, "/app/src/commands.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-001")
	testutil.MustNotFindRule(t, result, "GTSS-FW-TAURI-003")
}
