package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# Template Injection (SSTI) tests
// =========================================================================

func TestCSharp_Handlebars_TemplateInjection(t *testing.T) {
	code := `
using System;
using HandlebarsDotNet;

public class Handler {
    public string Handle() {
        string userTemplate = Console.ReadLine();
        var compiled = Handlebars.Compile(userTemplate);
        return compiled(new { Name = "test" });
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for Console.ReadLine -> Handlebars.Compile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Fluid_TemplateInjection(t *testing.T) {
	code := `
using System;
using Fluid;

public class Handler {
    public string Handle() {
        string userTemplate = Console.ReadLine();
        var parser = new FluidParser();
        var template = parser.Parse(userTemplate);
        return template.Render();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for Console.ReadLine -> FluidParser.Parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Handlebars_CompileView(t *testing.T) {
	code := `
using System;
using HandlebarsDotNet;

public class Handler {
    public string Handle() {
        string userTemplate = Console.ReadLine();
        var compiled = Handlebars.CompileView(userTemplate);
        return compiled(new { Name = "test" });
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for Console.ReadLine -> Handlebars.CompileView")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# LDAP Injection tests
// =========================================================================

func TestCSharp_LDAP_SearchRequest(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.Protocols;

public class Handler {
    public void Handle() {
        string filter = Console.ReadLine();
        var request = new SearchRequest("dc=example,dc=com", filter, SearchScope.Subtree);
        var conn = new LdapConnection("ldap.example.com");
        conn.SendRequest(request);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for Console.ReadLine -> new SearchRequest")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_LDAP_SearchRequest_Safe(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.Protocols;
using System.Web.Security.AntiXss;

public class Handler {
    public void Handle() {
        string userInput = Console.ReadLine();
        string safeInput = LdapFilterEncoder.FilterEncode(userInput);
        var request = new SearchRequest("dc=example,dc=com", safeInput, SearchScope.Subtree);
        var conn = new LdapConnection("ldap.example.com");
        conn.SendRequest(request);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP && f.Confidence > 0.5 {
			t.Errorf("expected LDAP flow to be sanitized by LdapFilterEncoder.FilterEncode, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_LDAP_SendRequest(t *testing.T) {
	code := `
using System;
using System.DirectoryServices.Protocols;

public class Handler {
    public void Handle() {
        string filter = Console.ReadLine();
        var request = new SearchRequest("dc=example,dc=com", filter, SearchScope.Subtree);
        var conn = new LdapConnection("ldap.example.com");
        conn.SendRequest(request);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	ldapFound := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			ldapFound = true
			break
		}
	}
	if !ldapFound {
		t.Error("expected LDAP injection flow for Console.ReadLine -> LdapConnection.SendRequest")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# SQL Injection tests — ADO.NET providers
// =========================================================================

func TestCSharp_NpgsqlCommand_SQLInjection(t *testing.T) {
	code := `
using System;
using Npgsql;

public class Handler {
    public void Handle(NpgsqlConnection conn) {
        string input = Console.ReadLine();
        var cmd = new NpgsqlCommand("SELECT * FROM users WHERE name = '" + input + "'", conn);
        cmd.ExecuteReader();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Console.ReadLine -> new NpgsqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_NpgsqlCommand_Sanitized(t *testing.T) {
	code := `
using System;
using Npgsql;

public class Handler {
    public void Handle(NpgsqlConnection conn) {
        string input = Console.ReadLine();
        var cmd = new NpgsqlCommand("SELECT * FROM users WHERE name = @name", conn);
        cmd.Parameters.Add(new NpgsqlParameter("@name", input));
        cmd.ExecuteReader();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected SQL flow to be sanitized by NpgsqlParameter, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_MySqlCommand_SQLInjection(t *testing.T) {
	code := `
using System;
using MySqlConnector;

public class Handler {
    public void Handle(MySqlConnection conn) {
        string input = Console.ReadLine();
        var cmd = new MySqlCommand("DELETE FROM users WHERE id = " + input, conn);
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Console.ReadLine -> new MySqlCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SqliteCommand_SQLInjection(t *testing.T) {
	code := `
using System;
using Microsoft.Data.Sqlite;

public class Handler {
    public void Handle(SqliteConnection conn) {
        string input = Console.ReadLine();
        var cmd = new SqliteCommand("SELECT * FROM data WHERE key = '" + input + "'", conn);
        cmd.ExecuteScalar();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Console.ReadLine -> new SqliteCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_SqlDataAdapter_SQLInjection(t *testing.T) {
	code := `
using System;
using System.Data;
using System.Data.SqlClient;

public class Handler {
    public DataTable Handle(SqlConnection conn) {
        string input = Console.ReadLine();
        var adapter = new SqlDataAdapter("SELECT * FROM products WHERE category = '" + input + "'", conn);
        var dt = new DataTable();
        adapter.Fill(dt);
        return dt;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Console.ReadLine -> new SqlDataAdapter")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# SQL Injection tests — NHibernate
// =========================================================================

func TestCSharp_NHibernate_CreateSQLQuery(t *testing.T) {
	code := `
using System;
using NHibernate;

public class Handler {
    public void Handle(ISession session) {
        string input = Console.ReadLine();
        var query = session.CreateSQLQuery("SELECT * FROM users WHERE name = '" + input + "'");
        query.List();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Console.ReadLine -> session.CreateSQLQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_NHibernate_CreateQuery(t *testing.T) {
	code := `
using System;
using NHibernate;

public class Handler {
    public void Handle(ISession session) {
        string input = Console.ReadLine();
        var query = session.CreateQuery("FROM User WHERE name = '" + input + "'");
        query.List();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected HQL injection flow for Console.ReadLine -> session.CreateQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C# MongoDB NoSQL injection tests
// =========================================================================

func TestCSharp_MongoDB_BsonDocumentParse(t *testing.T) {
	code := `
using System;
using MongoDB.Bson;
using MongoDB.Driver;

public class Handler {
    public void Handle(IMongoCollection<BsonDocument> collection) {
        string input = Console.ReadLine();
        var filter = BsonDocument.Parse(input);
        collection.Find(filter);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for Console.ReadLine -> BsonDocument.Parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_MongoDB_RunCommand(t *testing.T) {
	code := `
using System;
using MongoDB.Bson;
using MongoDB.Driver;

public class Handler {
    public void Handle(IMongoDatabase db) {
        string input = Console.ReadLine();
        var cmdDoc = BsonDocument.Parse(input);
        db.RunCommand<BsonDocument>(cmdDoc);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkNoSQL) {
		t.Error("expected NoSQL injection flow for Console.ReadLine -> db.RunCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_MongoDB_Sanitized_BuildersFilter(t *testing.T) {
	code := `
using System;
using MongoDB.Bson;
using MongoDB.Driver;

public class Handler {
    public void Handle(IMongoCollection<BsonDocument> collection) {
        string input = Console.ReadLine();
        var filter = Builders<BsonDocument>.Filter.Eq("name", input);
        collection.Find(filter);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected MongoDB flow to be sanitized by Builders.Filter, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Safe patterns (should NOT produce taint flows for the target category)
// =========================================================================

// =========================================================================
// C# Path Traversal — FileRead sanitizer tests (CWE-22)
// =========================================================================

func TestCSharp_FileRead_Safe_GetFileNameWithoutExtension(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    public string Handle() {
        string userInput = Console.ReadLine();
        string safeName = Path.GetFileNameWithoutExtension(userInput);
        string path = Path.Combine("/uploads", safeName + ".txt");
        string content = File.ReadAllText(path);
        return content;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Errorf("expected FileRead flow to be sanitized by Path.GetFileNameWithoutExtension, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_FileRead_Safe_GetFullPathStartsWith(t *testing.T) {
	code := `
using System;
using System.IO;

public class Handler {
    private readonly string _baseDir = "/var/data/uploads";

    public string Handle() {
        string userInput = Console.ReadLine();
        string fullPath = Path.GetFullPath(userInput);
        if (!fullPath.StartsWith(_baseDir)) {
            return "rejected";
        }
        string content = File.ReadAllText(fullPath);
        return content;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Errorf("expected FileRead flow to be sanitized by Path.GetFullPath+StartsWith, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_FileRead_Safe_PhysicalFileProvider(t *testing.T) {
	code := `
using System;
using System.IO;
using Microsoft.Extensions.FileProviders;

public class Handler {
    public string Handle() {
        string userInput = Console.ReadLine();
        var provider = new PhysicalFileProvider("/var/data/uploads");
        var fileInfo = provider.GetFileInfo(userInput);
        using var stream = fileInfo.CreateReadStream();
        return "ok";
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Errorf("expected FileRead flow to be sanitized by PhysicalFileProvider, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_LDAP_Sanitized(t *testing.T) {
	code := `
using System;
using System.DirectoryServices;
using Microsoft.Security.Application;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        string safeFilter = Encoder.LdapFilterEncode(input);
        var searcher = new DirectorySearcher();
        searcher.Filter = safeFilter;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP && f.Confidence > 0.5 {
			t.Errorf("expected LDAP flow to be sanitized by LdapFilterEncode, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Trust Boundary sanitizer tests (CWE-501)
// =========================================================================

func TestCSharp_TrustBoundary_Vulnerable(t *testing.T) {
	code := `
using System;

public class Handler {
    public void Handle() {
        string input = Console.ReadLine();
        Session.SetString("userData", input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for Console.ReadLine -> Session.SetString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_TrustBoundary_Safe_FluentValidation(t *testing.T) {
	code := `
using System;
using FluentValidation;
using Microsoft.AspNetCore.Http;

public class Handler {
    private readonly IValidator<UserInput> _validator;

    public void Handle(HttpContext context) {
        string input = Console.ReadLine();
        var result = _validator.Validate(input);
        if (result.IsValid) {
            context.Session.SetString("userData", input);
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary && f.Confidence > 0.5 {
			t.Errorf("expected trust boundary flow to be sanitized by FluentValidation.Validate, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_TrustBoundary_Safe_DataAnnotations(t *testing.T) {
	code := `
using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

public class Handler {
    public void Handle(HttpContext context) {
        string input = Console.ReadLine();
        var results = new System.Collections.Generic.List<ValidationResult>();
        var ctx = new ValidationContext(input);
        if (Validator.TryValidateObject(input, ctx, results, true)) {
            context.Session.SetString("userData", input);
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary && f.Confidence > 0.5 {
			t.Errorf("expected trust boundary flow to be sanitized by Validator.TryValidateObject, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Crypto sanitizer tests (CWE-327/330)
// =========================================================================

func TestCSharp_Crypto_Vulnerable_MD5(t *testing.T) {
	code := `
using System;
using System.Security.Cryptography;

public class Handler {
    public byte[] Handle() {
        string algo = Console.ReadLine();
        var md5 = MD5.Create(algo);
        return md5.ComputeHash(new byte[] { 1, 2, 3 });
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak crypto flow for Console.ReadLine -> MD5.Create(algo)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Crypto_Safe_RandomNumberGenerator(t *testing.T) {
	code := `
using System;
using System.Security.Cryptography;

public class Handler {
    public string Handle() {
        string input = Console.ReadLine();
        byte[] token = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(token);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.5 {
			t.Errorf("expected crypto flow to be sanitized by RandomNumberGenerator.GetBytes, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_Crypto_Safe_HMACSHA256(t *testing.T) {
	code := `
using System;
using System.Security.Cryptography;

public class Handler {
    public byte[] Handle() {
        string input = Console.ReadLine();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.5 {
			t.Errorf("expected crypto flow to be sanitized by HMACSHA256, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_Crypto_Safe_AesGcm(t *testing.T) {
	code := `
using System;
using System.Security.Cryptography;

public class Handler {
    public byte[] Handle() {
        string input = Console.ReadLine();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        var aes = new AesGcm(key);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(input);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return ciphertext;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.5 {
			t.Errorf("expected crypto flow to be sanitized by AesGcm, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_Crypto_Safe_Argon2(t *testing.T) {
	code := `
using System;
using Konscious.Security.Cryptography;

public class Handler {
    public byte[] Handle() {
        string password = Console.ReadLine();
        var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password));
        argon2.Salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        argon2.DegreeOfParallelism = 4;
        argon2.MemorySize = 65536;
        argon2.Iterations = 3;
        return argon2.GetBytes(32);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.5 {
			t.Errorf("expected crypto flow to be sanitized by Argon2id, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_Crypto_Safe_FixedTimeEquals(t *testing.T) {
	code := `
using System;
using System.Security.Cryptography;

public class Handler {
    public bool Handle() {
        string input = Console.ReadLine();
        byte[] computed = System.Text.Encoding.UTF8.GetBytes(input);
        byte[] stored = new byte[] { 1, 2, 3 };
        return CryptographicOperations.FixedTimeEquals(computed, stored);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.5 {
			t.Errorf("expected crypto flow to be sanitized by CryptographicOperations.FixedTimeEquals, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_Crypto_Safe_KeyDerivation(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

public class Handler {
    public byte[] Handle() {
        string password = Console.ReadLine();
        byte[] salt = new byte[16];
        byte[] hash = KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, 100000, 32);
        return hash;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Confidence > 0.5 {
			t.Errorf("expected crypto flow to be sanitized by KeyDerivation.Pbkdf2, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Log Injection sanitizer tests (CWE-117)
// =========================================================================

func TestCSharp_LogInjection_Safe_LoggerMessageDefine(t *testing.T) {
	code := `
using System;
using Microsoft.Extensions.Logging;

public class Handler {
    private static readonly Action<ILogger, string, Exception> _logAction =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(1), "User action: {Action}");

    public void Handle(ILogger logger) {
        string input = Console.ReadLine();
        _logAction(logger, input, null);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected log flow to be sanitized by LoggerMessage.Define, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_LogInjection_Safe_LoggerMessageAttribute(t *testing.T) {
	code := `
using System;
using Microsoft.Extensions.Logging;

public partial class Handler {
    [LoggerMessage(EventId = 1, Level = LogLevel.Information, Message = "User action: {Action}")]
    partial void LogUserAction(string action);

    public void Handle() {
        string input = Console.ReadLine();
        LogUserAction(input);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected log flow to be sanitized by [LoggerMessage] attribute, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Header Injection sanitizer tests (CWE-113)
// =========================================================================

func TestCSharp_Header_Safe_ContentDisposition(t *testing.T) {
	code := `
using System;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;

public class Handler {
    public void Handle(HttpResponse response) {
        string filename = Console.ReadLine();
        var cd = new ContentDispositionHeaderValue("attachment");
        cd.FileNameStar = filename;
        response.Headers.Append("Content-Disposition", cd.ToString());
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader && f.Confidence > 0.5 {
			t.Errorf("expected header flow to be sanitized by ContentDispositionHeaderValue, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_Header_Safe_ReplaceNewline(t *testing.T) {
	code := `
using System;
using Microsoft.AspNetCore.Http;

public class Handler {
    public void Handle(HttpResponse response) {
        string value = Console.ReadLine();
        string safe = value.Replace(Environment.NewLine, "");
        response.Headers.Append("X-Custom", safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader && f.Confidence > 0.5 {
			t.Errorf("expected header flow to be sanitized by Replace(Environment.NewLine), got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# SSRF sanitizer tests (CWE-918)
// =========================================================================

func TestCSharp_SSRF_Safe_CheckHostName(t *testing.T) {
	code := `
using System;
using System.Net.Http;

public class Handler {
    public void Handle() {
        string url = Console.ReadLine();
        var uri = new Uri(url);
        var hostType = Uri.CheckHostName(uri.Host);
        if (hostType == UriHostNameType.Dns) {
            var client = new HttpClient();
            client.GetAsync(url);
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	// The HttpClient.GetAsync SSRF sink is live (receiver-aliased), so a flow
	// IS reported here; the Uri.CheckHostName guard must demote it below the
	// 0.7 block threshold (a guarded SSRF is a hint, not a block). An unguarded
	// client.GetAsync(url) scores 1.0, so any value < 0.7 proves the sanitizer
	// is applied.
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence >= 0.7 {
			t.Errorf("expected SSRF flow to be demoted below block threshold by Uri.CheckHostName, got confidence %.2f", f.Confidence)
		}
	}
}

func TestCSharp_SSRF_Safe_IsWellFormed(t *testing.T) {
	code := `
using System;
using System.Net.Http;

public class Handler {
    public void Handle() {
        string url = Console.ReadLine();
        if (Uri.IsWellFormedUriString(url, UriKind.Absolute)) {
            var client = new HttpClient();
            client.GetAsync(url);
        }
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	// The HttpClient.GetAsync SSRF sink is live (receiver-aliased), so a flow
	// IS reported here; the Uri.IsWellFormedUriString guard must demote it below
	// the 0.7 block threshold (a guarded SSRF is a hint, not a block). An
	// unguarded client.GetAsync(url) scores 1.0, so any value < 0.7 proves the
	// sanitizer is applied.
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence >= 0.7 {
			t.Errorf("expected SSRF flow to be demoted below block threshold by Uri.IsWellFormedUriString, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Eval sanitizer tests (CWE-94/95)
// =========================================================================

func TestCSharp_Eval_Safe_ExpressionLambda(t *testing.T) {
	code := `
using System;
using System.Linq.Expressions;

public class Handler {
    public int Handle() {
        string input = Console.ReadLine();
        int value = int.Parse(input);
        var param = Expression.Constant(value);
        var expr = Expression.Lambda<Func<int>>(param);
        var compiled = expr.Compile();
        return compiled();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Confidence > 0.5 {
			t.Errorf("expected eval flow to be sanitized by Expression.Lambda, got confidence %.2f", f.Confidence)
		}
	}
}

// =========================================================================
// C# Template Injection tests (DotLiquid / RazorLight / Cottle)
// =========================================================================

func TestCSharp_DotLiquid_TemplateInjection(t *testing.T) {
	code := `
using System;
using DotLiquid;

public class Handler {
    public string Handle() {
        string userTemplate = Console.ReadLine();
        var template = DotLiquid.Template.Parse(userTemplate);
        return template.Render(Hash.FromAnonymousObject(new { Name = "test" }));
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for Console.ReadLine -> DotLiquid.Template.Parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_RazorLight_CompileRenderStringAsync(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using RazorLight;

public class Handler {
    public async Task<string> Handle(IRazorLightEngine engine) {
        string userTemplate = Console.ReadLine();
        var model = new { Name = "test" };
        return await engine.CompileRenderStringAsync("key", userTemplate, model);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for Console.ReadLine -> RazorLight.CompileRenderStringAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Cottle_DocumentCreateDefault(t *testing.T) {
	code := `
using System;
using Cottle;

public class Handler {
    public string Handle() {
        string userTemplate = Console.ReadLine();
        var document = Cottle.Document.CreateDefault(userTemplate).DocumentOrThrow;
        return document.Render(Context.Empty);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkTemplate) {
		t.Error("expected template injection flow for Console.ReadLine -> Cottle.Document.CreateDefault")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
