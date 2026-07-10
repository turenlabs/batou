package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ===========================================================================
// C# database source tests — validates EF Core, Dapper async, and ADO.NET
// async source entries produce taint flows to known sinks (second-order
// injection detection).
// ===========================================================================

// --- ADO.NET async ---

func TestCSharp_Source_ExecuteReaderAsync(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Handler {
    public async void Handle(SqlConnection conn) {
        var cmd1 = new SqlCommand("SELECT name FROM users WHERE id = 1", conn);
        var name = await cmd1.ExecuteReaderAsync();
        var cmd2 = new SqlCommand("SELECT * FROM orders WHERE customer = '" + name + "'");
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ExecuteReaderAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_ExecuteScalarAsync(t *testing.T) {
	code := `
using System;
using System.Data.SqlClient;

public class Handler {
    public async void Handle(SqlConnection conn) {
        var cmd1 = new SqlCommand("SELECT template FROM pages WHERE id = 1", conn);
        var template = await cmd1.ExecuteScalarAsync();
        var cmd2 = new SqlCommand("SELECT * FROM data WHERE key = '" + template + "'");
        cmd2.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for ExecuteScalarAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Dapper async ---

func TestCSharp_Source_Dapper_QueryAsync(t *testing.T) {
	code := `
using System;
using Dapper;
using System.Data.SqlClient;

public class Handler {
    public async void Handle(SqlConnection conn) {
        var name = await conn.QueryAsync<string>("SELECT name FROM users");
        var cmd = new SqlCommand("SELECT * FROM orders WHERE customer = '" + name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for Dapper.QueryAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_Dapper_QueryFirstAsync(t *testing.T) {
	code := `
using System;
using Dapper;
using System.Data.SqlClient;

public class Handler {
    public async void Handle(SqlConnection conn) {
        var name = await conn.QueryFirstAsync<string>("SELECT name FROM users WHERE id = 1");
        var cmd = new SqlCommand("SELECT * FROM orders WHERE customer = '" + name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for Dapper.QueryFirstAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_Dapper_QueryMultiple(t *testing.T) {
	code := `
using System;
using Dapper;
using System.Data.SqlClient;

public class Handler {
    public void Handle(SqlConnection conn) {
        var name = conn.QueryMultiple("SELECT name FROM users");
        var cmd = new SqlCommand("SELECT * FROM orders WHERE customer = '" + name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for Dapper.QueryMultiple -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Entity Framework Core ---

func TestCSharp_Source_EFCore_FindAsync(t *testing.T) {
	code := `
using System;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlClient;

public class Handler {
    private readonly MyDbContext _context;

    public async void Handle(int id) {
        var user = await _context.Users.FindAsync(id);
        var cmd = new SqlCommand("SELECT * FROM audit WHERE user = '" + user.Name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for EF Core FindAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_EFCore_ToListAsync(t *testing.T) {
	code := `
using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlClient;

public class Handler {
    private readonly MyDbContext _context;

    public async void Handle() {
        var data = await _context.Users.ToListAsync();
        var cmd = new SqlCommand("SELECT * FROM audit WHERE user = '" + data + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for EF Core ToListAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_EFCore_FirstOrDefaultAsync(t *testing.T) {
	code := `
using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlClient;

public class Handler {
    private readonly MyDbContext _context;

    public async void Handle(string email) {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
        var cmd = new SqlCommand("SELECT * FROM orders WHERE customer = '" + user.Name + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for EF Core FirstOrDefaultAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Source_EFCore_SingleOrDefaultAsync(t *testing.T) {
	code := `
using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlClient;

public class Handler {
    private readonly MyDbContext _context;

    public async void Handle(int orderId) {
        var order = await _context.Orders.SingleOrDefaultAsync(o => o.Id == orderId);
        var cmd = new SqlCommand("SELECT * FROM items WHERE desc = '" + order.Description + "'");
        cmd.ExecuteNonQuery();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for EF Core SingleOrDefaultAsync -> SqlCommand (second-order injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
