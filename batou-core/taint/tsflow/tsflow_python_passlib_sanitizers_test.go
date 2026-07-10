package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// passlib password hashing/verification sanitizer tests.
//
// passlib exposes one PasswordHash object per algorithm under passlib.hash.
// The canonical idiom is:
//   from passlib.hash import bcrypt   # or argon2, pbkdf2_sha256, ...
//   bcrypt.hash(secret)               # plaintext at args[0]
//   bcrypt.verify(secret, stored)     # plaintext at args[0]
//
// Each sanitized test pairs a tainted Flask request param with a SnkCrypto
// sink (hashlib.md5) downstream. The sanitizer should clear the SnkCrypto
// category off the flow so the md5 call does not fire. The Unsanitized
// baseline confirms the underlying source -> sink path is detected without
// the sanitizer.
//
// All call sites are wrapped in `def handler()` because the Python tsflow
// walker only descends into function_definition bodies.
// =========================================================================

func TestPython_Passlib_Unsanitized_Baseline(t *testing.T) {
	code := `
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    hashlib.md5(password.encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow when raw request.args password reaches hashlib.md5")
	}
}

func TestPython_Passlib_Bcrypt_Hash_Sanitized(t *testing.T) {
	code := `
from passlib.hash import bcrypt
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    safe = bcrypt.hash(password)
    hashlib.md5(safe.encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.bcrypt.hash() should neutralize SnkCrypto taint")
		}
	}
}

func TestPython_Passlib_Bcrypt_Verify_Sanitized(t *testing.T) {
	code := `
from passlib.hash import bcrypt
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    ok = bcrypt.verify(password, "$2b$12$abcdefghijklmnopqrstuvwx")
    hashlib.md5(str(ok).encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.bcrypt.verify() should neutralize SnkCrypto taint")
		}
	}
}

func TestPython_Passlib_Argon2_Hash_Sanitized(t *testing.T) {
	code := `
from passlib.hash import argon2
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    safe = argon2.hash(password)
    hashlib.md5(safe.encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.argon2.hash() should neutralize SnkCrypto taint")
		}
	}
}

func TestPython_Passlib_Argon2_Verify_Sanitized(t *testing.T) {
	code := `
from passlib.hash import argon2
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    ok = argon2.verify(password, "$argon2id$v=19$m=65536,t=3,p=4$abc$def")
    hashlib.md5(str(ok).encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.argon2.verify() should neutralize SnkCrypto taint")
		}
	}
}

func TestPython_Passlib_Pbkdf2Sha256_Hash_Sanitized(t *testing.T) {
	code := `
from passlib.hash import pbkdf2_sha256
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    safe = pbkdf2_sha256.hash(password)
    hashlib.md5(safe.encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.pbkdf2_sha256.hash() should neutralize SnkCrypto taint")
		}
	}
}

func TestPython_Passlib_Pbkdf2Sha256_Verify_Sanitized(t *testing.T) {
	code := `
from passlib.hash import pbkdf2_sha256
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    ok = pbkdf2_sha256.verify(password, "$pbkdf2-sha256$29000$abc$def")
    hashlib.md5(str(ok).encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.pbkdf2_sha256.verify() should neutralize SnkCrypto taint")
		}
	}
}

func TestPython_Passlib_Pbkdf2Sha512_Hash_Sanitized(t *testing.T) {
	code := `
from passlib.hash import pbkdf2_sha512
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    safe = pbkdf2_sha512.hash(password)
    hashlib.md5(safe.encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.pbkdf2_sha512.hash() should neutralize SnkCrypto taint")
		}
	}
}

func TestPython_Passlib_Pbkdf2Sha512_Verify_Sanitized(t *testing.T) {
	code := `
from passlib.hash import pbkdf2_sha512
from flask import request
import hashlib

def handler():
    password = request.args.get("password")
    ok = pbkdf2_sha512.verify(password, "$pbkdf2-sha512$25000$abc$def")
    hashlib.md5(str(ok).encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("passlib.hash.pbkdf2_sha512.verify() should neutralize SnkCrypto taint")
		}
	}
}

// Negative-control: code that uses bcrypt.hash on a CONSTANT (not user input)
// must produce zero flows — the sanitizer should not invent flows where there
// is no source. Guards against a degenerate matcher that flags every call.
func TestPython_Passlib_NoSource_NoFlow(t *testing.T) {
	code := `
from passlib.hash import bcrypt
import hashlib

def handler():
    safe = bcrypt.hash("constant-password")
    hashlib.md5(safe.encode())
`
	flows := Analyze(code, "/app/handler.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("constant password through bcrypt.hash should produce no SnkCrypto flow")
		}
	}
}
