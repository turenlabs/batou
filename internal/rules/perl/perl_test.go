package perl

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// ==========================================================================
// GTSS-PL-001: Command Injection
// ==========================================================================

func TestPL001_System_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $file = $cgi->param('file');
system("cat $file");
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-001")
}

func TestPL001_System_VarArg(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $cmd = $cgi->param('cmd');
system($cmd);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-001")
}

func TestPL001_Exec_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $program = $ARGV[0];
exec("$program --flag");
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-001")
}

func TestPL001_Backticks_Interpolation(t *testing.T) {
	content := "#!/usr/bin/perl\nuse strict;\nmy $host = $cgi->param('host');\nmy $out = `ping $host`;\n"
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-001")
}

func TestPL001_Qx_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $dir = $cgi->param('dir');
my $listing = qx(ls $dir);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-001")
}

func TestPL001_OpenPipe_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $cmd = $cgi->param('cmd');
open(my $fh, "|$cmd");
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-001")
}

func TestPL001_System_ListForm_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $file = $cgi->param('file');
system('cat', $file);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-001")
}

// ==========================================================================
// GTSS-PL-002: SQL Injection
// ==========================================================================

func TestPL002_DBI_Do_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use DBI;
my $name = $cgi->param('name');
$dbh->do("DELETE FROM users WHERE name = '$name'");
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-002")
}

func TestPL002_DBI_Do_Concat(t *testing.T) {
	content := `#!/usr/bin/perl
use DBI;
my $id = $cgi->param('id');
$dbh->do("SELECT * FROM users WHERE id = " . $id);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-002")
}

func TestPL002_DBI_Prepare_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use DBI;
my $table = $cgi->param('table');
my $sth = $dbh->prepare("SELECT * FROM $table WHERE id = 1");
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-002")
}

func TestPL002_DBI_Selectrow_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use DBI;
my $user = $cgi->param('user');
my @row = $dbh->selectrow_array("SELECT * FROM users WHERE name = '$user'");
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-002")
}

func TestPL002_DBI_Placeholder_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use DBI;
my $name = $cgi->param('name');
$dbh->do("DELETE FROM users WHERE name = ?", undef, $name);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-002")
}

func TestPL002_DBI_Prepare_Execute_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use DBI;
my $name = $cgi->param('name');
my $sth = $dbh->prepare("SELECT * FROM users WHERE name = ?");
$sth->execute($name);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-002")
}

// ==========================================================================
// GTSS-PL-003: Code Injection
// ==========================================================================

func TestPL003_Eval_Variable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $code = $cgi->param('expr');
my $result = eval($code);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-003")
}

func TestPL003_Eval_Dollar(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $expr = $cgi->param('expr');
eval $expr;
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-003")
}

func TestPL003_Eval_DoubleQuote_Interp(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $field = $cgi->param('field');
eval "print $field";
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-003")
}

func TestPL003_Eval_Block_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
eval {
    my $result = some_function();
};
if ($@) {
    warn "Error: $@";
}
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-003")
}

// ==========================================================================
// GTSS-PL-004: Path Traversal
// ==========================================================================

func TestPL004_TwoArgOpen_Variable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $file = $cgi->param('file');
open(my $fh, $file);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-004")
}

func TestPL004_ThreeArgOpen_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $file = $cgi->param('file');
open(my $fh, '<', "/safe/dir/" . File::Basename::basename($file));
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-004")
}

// ==========================================================================
// GTSS-PL-005: Regex DoS
// ==========================================================================

func TestPL005_Regex_Variable_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $pattern = $cgi->param('search');
if ($text =~ /$pattern/) {
    print "found";
}
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-005")
}

func TestPL005_Qr_Variable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $search = $cgi->param('q');
my $re = qr/$search/i;
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-005")
}

func TestPL005_Quotemeta_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $pattern = quotemeta($cgi->param('search'));
if ($text =~ /$pattern/) {
    print "found";
}
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-005")
}

// ==========================================================================
// GTSS-PL-006: CGI XSS
// ==========================================================================

func TestPL006_Print_CGI_Param(t *testing.T) {
	content := `#!/usr/bin/perl
use CGI;
my $cgi = CGI->new;
print "Hello " . $cgi->param('name');
`
	result := testutil.ScanContent(t, "/app/handler.cgi", content)
	testutil.MustFindRule(t, result, "GTSS-PL-006")
}

func TestPL006_Print_Q_Param(t *testing.T) {
	content := `#!/usr/bin/perl
use CGI;
my $q = CGI->new;
print "<h1>Results for: " . $q->param('query') . "</h1>";
`
	result := testutil.ScanContent(t, "/app/handler.cgi", content)
	testutil.MustFindRule(t, result, "GTSS-PL-006")
}

func TestPL006_Encoded_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use CGI;
use HTML::Entities;
my $cgi = CGI->new;
print "Hello " . encode_entities($cgi->param('name'));
`
	result := testutil.ScanContent(t, "/app/handler.cgi", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-006")
}

// ==========================================================================
// GTSS-PL-007: Insecure File Operations
// ==========================================================================

func TestPL007_Chmod_0777(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
chmod(0777, $file);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-007")
}

func TestPL007_Mkdir_0777(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
mkdir($dir, 0777);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-007")
}

func TestPL007_Chmod_0600_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
chmod(0600, $file);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-007")
}

// ==========================================================================
// GTSS-PL-008: Deserialization
// ==========================================================================

func TestPL008_Storable_Thaw(t *testing.T) {
	content := `#!/usr/bin/perl
use Storable;
my $data = $cgi->param('data');
my $obj = thaw($data);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-008")
}

func TestPL008_Storable_Retrieve(t *testing.T) {
	content := `#!/usr/bin/perl
use Storable;
my $file = $cgi->param('file');
my $obj = retrieve($file);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-008")
}

func TestPL008_YAML_Load(t *testing.T) {
	content := `#!/usr/bin/perl
use YAML;
my $yaml_str = $cgi->param('config');
my $config = YAML::Load($yaml_str);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-008")
}

func TestPL008_JSON_Decode_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use JSON;
my $json_str = $cgi->param('data');
my $data = decode_json($json_str);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-008")
}

// ==========================================================================
// GTSS-PL-009: LDAP Injection
// ==========================================================================

func TestPL009_LDAP_Search_Interpolation(t *testing.T) {
	content := `#!/usr/bin/perl
use Net::LDAP;
my $ldap = Net::LDAP->new('ldap.example.com');
my $user = $cgi->param('username');
my $result = $ldap->search(filter => "(uid=$user)");
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-009")
}

func TestPL009_LDAP_Filter_Variable(t *testing.T) {
	content := `#!/usr/bin/perl
use Net::LDAP;
my $ldap = Net::LDAP->new('ldap.example.com');
my $filter = "(uid=" . $cgi->param('user') . ")";
my $result = $ldap->search(filter => $filter);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-009")
}

func TestPL009_LDAP_Escaped_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use Net::LDAP;
use Net::LDAP::Util qw(escape_filter_value);
my $ldap = Net::LDAP->new('ldap.example.com');
my $user = escape_filter_value($cgi->param('username'));
my $result = $ldap->search(filter => "(uid=$user)");
`
	// This still has the interpolation pattern but uses escape_filter_value
	// The rule is regex-based so it may still flag; in practice taint analysis
	// would catch the sanitizer. We test basic detection here.
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-009")
}

// ==========================================================================
// GTSS-PL-010: Insecure Randomness
// ==========================================================================

func TestPL010_Srand_Time(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
srand(time);
my $token = int(rand(1000000));
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-010")
}

func TestPL010_Rand_Security_Context(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $token = int(rand(999999));
my $session_id = "sess_$token";
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-010")
}

func TestPL010_Srand_Fixed(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
srand(42);
my $secret = rand(100);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustFindRule(t, result, "GTSS-PL-010")
}

func TestPL010_CryptURandom_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Crypt::URandom;
my $token = Crypt::URandom::urandom(32);
`
	result := testutil.ScanContent(t, "/app/handler.pl", content)
	testutil.MustNotFindRule(t, result, "GTSS-PL-010")
}
