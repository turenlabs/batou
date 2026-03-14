package perl

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ==========================================================================
// BATOU-PL-019: Two-Argument Open Shell Injection
// ==========================================================================

func TestPL019_TwoArgOpen_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $filename = $cgi->param('file');
open(FH, $filename);
while (<FH>) { print; }
close(FH);
`
	result := testutil.ScanContent(t, "/app/reader.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-019")
}

func TestPL019_TwoArgOpen_MyFH_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $path = $ARGV[0];
open(my $fh, $path);
print <$fh>;
`
	result := testutil.ScanContent(t, "/app/reader.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-019")
}

func TestPL019_ThreeArgOpen_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $filename = $cgi->param('file');
open(my $fh, '<', $filename) or die "Cannot open: $!";
while (<$fh>) { print; }
close($fh);
`
	result := testutil.ScanContent(t, "/app/reader.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-019")
}

func TestPL019_TwoArgOpenMode_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
open(my $fh, ">output.txt") or die $!;
print $fh "hello";
close($fh);
`
	result := testutil.ScanContent(t, "/app/writer.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-019")
}

// ==========================================================================
// BATOU-PL-020: Storable::thaw on Network Data
// ==========================================================================

func TestPL020_StorableThaw_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Storable qw(thaw);
use IO::Socket::INET;

my $sock = IO::Socket::INET->new(
    LocalPort => 8080,
    Proto     => 'tcp',
    Listen    => 5,
);
my $client = $sock->accept();
my $data;
$client->recv($data, 4096);
my $obj = thaw($data);
`
	result := testutil.ScanContent(t, "/app/server.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-020")
}

func TestPL020_StorableThaw_QualifiedName_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Storable;
use IO::Socket;

my $socket = IO::Socket::INET->new(PeerAddr => 'example.com:9090');
$socket->recv(my $raw, 8192);
my $result = Storable::thaw($raw);
`
	result := testutil.ScanContent(t, "/app/client.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-020")
}

func TestPL020_StorableThaw_NoNetwork_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Storable qw(thaw freeze);

my $frozen = freeze({ name => 'test', value => 42 });
my $obj = thaw($frozen);
print $obj->{name};
`
	result := testutil.ScanContent(t, "/app/cache.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-020")
}

// ==========================================================================
// BATOU-PL-021: CGI Response Splitting
// ==========================================================================

func TestPL021_PrintCRLF_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use CGI;
my $q = CGI->new;
my $url = $q->param('url');
print "Location: \r\n\r\n$url";
`
	result := testutil.ScanContent(t, "/app/redirect.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-021")
}

func TestPL021_HeaderVar_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use CGI;
my $q = CGI->new;
my $location = $q->param('next');
print "Location: $location\r\n\r\n";
`
	result := testutil.ScanContent(t, "/app/redirect.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-021")
}

func TestPL021_StaticHeader_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use CGI;
my $q = CGI->new;
print $q->header('text/html');
print "<html><body>Hello</body></html>";
`
	result := testutil.ScanContent(t, "/app/page.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-021")
}

// ==========================================================================
// BATOU-PL-022: DBI do() with Interpolation
// ==========================================================================

func TestPL022_DbiDoInterp_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use DBI;
my $dbh = DBI->connect("dbi:mysql:testdb", "user", "pass");
my $table = $cgi->param('table');
$dbh->do("DROP TABLE $table");
`
	result := testutil.ScanContent(t, "/app/admin.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-022")
}

func TestPL022_DbiDoConcat_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use DBI;
my $dbh = DBI->connect("dbi:mysql:testdb", "user", "pass");
my $id = $cgi->param('id');
$dbh->do("DELETE FROM users WHERE id = " . $id);
`
	result := testutil.ScanContent(t, "/app/admin.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-022")
}

func TestPL022_DbiDoPlaceholder_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use DBI;
my $dbh = DBI->connect("dbi:mysql:testdb", "user", "pass");
my $id = $cgi->param('id');
$dbh->do("DELETE FROM users WHERE id = ?", undef, $id);
`
	result := testutil.ScanContent(t, "/app/admin.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-022")
}

// ==========================================================================
// BATOU-PL-023: require with Variable
// ==========================================================================

func TestPL023_RequireVar_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $module = $cgi->param('plugin');
require $module;
$module->new()->run();
`
	result := testutil.ScanContent(t, "/app/loader.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-023")
}

func TestPL023_RequireLiteral_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
require Digest::SHA;
require "config.pl";
`
	result := testutil.ScanContent(t, "/app/loader.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-023")
}

// ==========================================================================
// BATOU-PL-024: Regex with User Input ReDoS
// ==========================================================================

func TestPL024_RegexMatch_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $pattern = $cgi->param('search');
if ($input =~ /$pattern/) {
    print "Match found\n";
}
`
	result := testutil.ScanContent(t, "/app/search.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-024")
}

func TestPL024_QrCompile_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
my $filter = $cgi->param('filter');
my $re = qr/$filter/i;
my @matches = grep { $_ =~ $re } @items;
`
	result := testutil.ScanContent(t, "/app/filter.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-024")
}

func TestPL024_LiteralRegex_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
if ($email =~ /^[a-zA-Z0-9.]+@[a-zA-Z0-9.]+$/) {
    print "Valid email\n";
}
`
	result := testutil.ScanContent(t, "/app/validate.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-024")
}

// ==========================================================================
// BATOU-PL-025: Weak Hash for Passwords
// ==========================================================================

func TestPL025_MD5Password_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Digest::MD5 qw(md5_hex);

sub store_password {
    my ($username, $password) = @_;
    my $hash = md5_hex($password);
    $dbh->do("INSERT INTO users (name, pwd) VALUES (?, ?)", undef, $username, $hash);
}
`
	result := testutil.ScanContent(t, "/app/auth.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-025")
}

func TestPL025_SHA1Password_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Digest::SHA1;

my $passwd = $cgi->param('passwd');
my $sha1 = Digest::SHA1->new;
$sha1->add($passwd);
my $hash = $sha1->hexdigest;
`
	result := testutil.ScanContent(t, "/app/auth.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-025")
}

func TestPL025_MD5NoPassword_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Digest::MD5 qw(md5_hex);

my $checksum = md5_hex($file_contents);
print "File checksum: $checksum\n";
`
	result := testutil.ScanContent(t, "/app/checksum.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-025")
}

// ==========================================================================
// BATOU-PL-026: MIME::Lite Header Injection
// ==========================================================================

func TestPL026_MimeLiteVarHeader_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use MIME::Lite;

my $recipient = $cgi->param('email');
my $msg = MIME::Lite->new(
    From    => 'noreply@example.com',
    To      => $recipient,
    Subject => 'Welcome',
    Data    => 'Hello!',
);
$msg->send;
`
	result := testutil.ScanContent(t, "/app/mailer.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-026")
}

func TestPL026_MimeLiteStaticHeaders_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use MIME::Lite;

my $msg = MIME::Lite->new(
    From    => 'noreply@example.com',
    To      => 'admin@example.com',
    Subject => 'Daily Report',
    Data    => 'Report content here.',
);
$msg->send;
`
	result := testutil.ScanContent(t, "/app/mailer.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-026")
}

// ==========================================================================
// BATOU-PL-027: CGI::Cookie Parse DoS
// ==========================================================================

func TestPL027_CGICookieParse_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use CGI::Cookie;

my $raw_cookie = $ENV{'HTTP_COOKIE'};
my %cookies = CGI::Cookie->parse($raw_cookie);
my $session = $cookies{'session_id'}->value;
`
	result := testutil.ScanContent(t, "/app/session.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-027")
}

func TestPL027_CookieBaker_Safe(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use Cookie::Baker;

my $raw_cookie = $ENV{'HTTP_COOKIE'};
my $cookies = crush_cookie($raw_cookie);
my $session = $cookies->{'session_id'};
`
	result := testutil.ScanContent(t, "/app/session.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-027")
}

// ==========================================================================
// BATOU-PL-028: Taint Mode Disabled
// ==========================================================================

func TestPL028_NoTaintFlag_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/perl
use strict;
use warnings;
my $input = <STDIN>;
system("echo $input");
`
	result := testutil.ScanContent(t, "/app/script.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-028")
}

func TestPL028_EnvPerlNoTaint_Vulnerable(t *testing.T) {
	content := `#!/usr/bin/env perl
use strict;
use warnings;
print "Hello World\n";
`
	result := testutil.ScanContent(t, "/app/hello.pl", content)
	testutil.MustFindRule(t, result, "BATOU-PL-028")
}

func TestPL028_TaintEnabled_Safe(t *testing.T) {
	content := `#!/usr/bin/perl -T
use strict;
use warnings;
my $input = <STDIN>;
chomp $input;
if ($input =~ /^(\w+)$/) {
    system("echo", $1);
}
`
	result := testutil.ScanContent(t, "/app/script.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-028")
}

func TestPL028_NoShebang_Safe(t *testing.T) {
	content := `use strict;
use warnings;
sub process {
    my ($data) = @_;
    return uc($data);
}
`
	result := testutil.ScanContent(t, "/app/lib.pl", content)
	testutil.MustNotFindRule(t, result, "BATOU-PL-028")
}
