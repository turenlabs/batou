#!/usr/bin/env python3
"""Generate OWASP-style benchmark fixtures for Perl, Lua, and Groovy."""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ============================================================================
# PERL fixtures (80 cases: 4 categories x 20 each, alternating vuln/safe)
# ============================================================================

PERL_SQLI_VULN = [
    # 1: DBI do with interpolation (CGI)
    '''\
use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('name');
my $dbh = DBI->connect("dbi:mysql:testdb", "root", "");
$dbh->do("SELECT * FROM users WHERE name = '$name'");
''',
    # 3: DBI do with interpolation
    '''\
use Mojolicious::Lite;
get '/search' => sub {
    my $c = shift;
    my $query = $c->param('q');
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    $dbh->do("SELECT * FROM items WHERE title LIKE '%$query%'");
};
app->start;
''',
    # 5: selectrow_arrayref with interpolation
    '''\
use CGI;
my $q = CGI->new;
my $id = $q->param('id');
my $dbh = DBI->connect("dbi:mysql:app", "user", "pass");
my $row = $dbh->selectrow_arrayref("SELECT * FROM orders WHERE id = $id");
print "Content-type: text/html\\n\\n";
print $row->[1];
''',
    # 7: prepare with interpolated string
    '''\
use Dancer2;
get '/user/:id' => sub {
    my $id = params->{id};
    my $dbh = DBI->connect("dbi:SQLite:dbname=app.db");
    my $sth = $dbh->prepare("SELECT * FROM users WHERE id = $id");
    $sth->execute();
    return $sth->fetchrow_hashref();
};
''',
    # 9: do with variable interpolation (Mojolicious)
    '''\
use Mojolicious::Lite;
post '/login' => sub {
    my $c = shift;
    my $user = $c->param('username');
    my $pass = $c->param('password');
    my $dbh = DBI->connect("dbi:mysql:auth", "root", "");
    $dbh->do("SELECT * FROM accounts WHERE user='$user' AND pass='$pass'");
};
app->start;
''',
    # 11: selectall_arrayref with interpolation
    '''\
use CGI;
my $cgi = CGI->new;
my $dept = $cgi->param('department');
my $dbh = DBI->connect("dbi:Pg:dbname=hr", "admin", "secret");
my $rows = $dbh->selectall_arrayref("SELECT name, salary FROM employees WHERE dept = '$dept'");
''',
    # 13: do with GString-like interpolation (Dancer2)
    '''\
use Dancer2;
get '/products' => sub {
    my $category = params->{cat};
    my $dbh = DBI->connect("dbi:mysql:shop");
    $dbh->do("DELETE FROM products WHERE category = '$category'");
    return { status => 'deleted' };
};
''',
    # 15: Two queries with interpolation
    '''\
use CGI;
my $q = CGI->new;
my $table = $q->param('table');
my $dbh = DBI->connect("dbi:mysql:analytics");
my $count = $dbh->selectrow_arrayref("SELECT COUNT(*) FROM $table");
print "Content-type: text/html\\n\\n$count->[0]";
''',
    # 17: selectrow_hashref with var
    '''\
use Mojolicious::Lite;
get '/order' => sub {
    my $c = shift;
    my $order_id = $c->param('oid');
    my $dbh = DBI->connect("dbi:Pg:dbname=store");
    my $row = $dbh->selectrow_hashref("SELECT * FROM orders WHERE oid = '$order_id'");
    $c->render(json => $row);
};
app->start;
''',
    # 19: do with interpolation
    '''\
use Dancer2;
post '/update' => sub {
    my $id = params->{id};
    my $status = params->{status};
    my $dbh = DBI->connect("dbi:SQLite:dbname=tasks.db");
    $dbh->do("UPDATE tasks SET status = '$status' WHERE id = $id");
    return { ok => 1 };
};
''',
]

PERL_SQLI_SAFE = [
    # 2: Parameterized with placeholders
    '''\
use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('name');
my $dbh = DBI->connect("dbi:mysql:testdb", "root", "");
my $sth = $dbh->prepare("SELECT * FROM users WHERE name = ?");
$sth->execute($name);
''',
    # 4: Parameterized prepare+execute
    '''\
use Mojolicious::Lite;
get '/search' => sub {
    my $c = shift;
    my $query = $c->param('q');
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    my $sth = $dbh->prepare("SELECT * FROM items WHERE title LIKE ?");
    $sth->execute("%$query%");
};
app->start;
''',
    # 6: Parameterized selectrow
    '''\
use CGI;
my $q = CGI->new;
my $id = $q->param('id');
my $dbh = DBI->connect("dbi:mysql:app", "user", "pass");
my $row = $dbh->selectrow_arrayref("SELECT * FROM orders WHERE id = ?", undef, $id);
print "Content-type: text/html\\n\\n";
print $row->[1];
''',
    # 8: Prepare with placeholder (Dancer2)
    '''\
use Dancer2;
get '/user/:id' => sub {
    my $id = params->{id};
    my $dbh = DBI->connect("dbi:SQLite:dbname=app.db");
    my $sth = $dbh->prepare("SELECT * FROM users WHERE id = ?");
    $sth->execute($id);
    return $sth->fetchrow_hashref();
};
''',
    # 10: Parameterized login (Mojolicious)
    '''\
use Mojolicious::Lite;
post '/login' => sub {
    my $c = shift;
    my $user = $c->param('username');
    my $pass = $c->param('password');
    my $dbh = DBI->connect("dbi:mysql:auth", "root", "");
    my $sth = $dbh->prepare("SELECT * FROM accounts WHERE user = ? AND pass = ?");
    $sth->execute($user, $pass);
};
app->start;
''',
    # 12: selectall with placeholder
    '''\
use CGI;
my $cgi = CGI->new;
my $dept = $cgi->param('department');
my $dbh = DBI->connect("dbi:Pg:dbname=hr", "admin", "secret");
my $rows = $dbh->selectall_arrayref("SELECT name, salary FROM employees WHERE dept = ?", undef, $dept);
''',
    # 14: Parameterized delete (Dancer2)
    '''\
use Dancer2;
get '/products' => sub {
    my $category = params->{cat};
    my $dbh = DBI->connect("dbi:mysql:shop");
    my $sth = $dbh->prepare("DELETE FROM products WHERE category = ?");
    $sth->execute($category);
    return { status => 'deleted' };
};
''',
    # 16: Hardcoded table name (safe)
    '''\
use CGI;
my $q = CGI->new;
my $dbh = DBI->connect("dbi:mysql:analytics");
my $count = $dbh->selectrow_arrayref("SELECT COUNT(*) FROM page_views");
print "Content-type: text/html\\n\\n$count->[0]";
''',
    # 18: Parameterized selectrow_hashref (Mojolicious)
    '''\
use Mojolicious::Lite;
get '/order' => sub {
    my $c = shift;
    my $order_id = $c->param('oid');
    my $dbh = DBI->connect("dbi:Pg:dbname=store");
    my $row = $dbh->selectrow_hashref("SELECT * FROM orders WHERE oid = ?", undef, $order_id);
    $c->render(json => $row);
};
app->start;
''',
    # 20: Parameterized update (Dancer2)
    '''\
use Dancer2;
post '/update' => sub {
    my $id = params->{id};
    my $status = params->{status};
    my $dbh = DBI->connect("dbi:SQLite:dbname=tasks.db");
    my $sth = $dbh->prepare("UPDATE tasks SET status = ? WHERE id = ?");
    $sth->execute($status, $id);
    return { ok => 1 };
};
''',
]

PERL_CMDI_VULN = [
    # 1: system with interpolated string
    '''\
use CGI;
my $cgi = CGI->new;
my $host = $cgi->param('host');
system("ping -c 4 $host");
''',
    # 3: backticks with var
    '''\
use Mojolicious::Lite;
get '/lookup' => sub {
    my $c = shift;
    my $domain = $c->param('domain');
    my $result = `nslookup $domain`;
    $c->render(text => $result);
};
app->start;
''',
    # 5: open pipe with var (pipe prefix form)
    '''\
use CGI;
my $q = CGI->new;
my $file = $q->param('file');
open(my $fh, "|cat $file");
my @lines = <$fh>;
close($fh);
print "Content-type: text/plain\\n\\n@lines";
''',
    # 7: exec with interpolation
    '''\
use Dancer2;
post '/convert' => sub {
    my $input = params->{filename};
    exec("convert $input output.png");
};
''',
    # 9: qx with var
    '''\
use CGI;
my $cgi = CGI->new;
my $cmd = $cgi->param('cmd');
my $output = qx(ls $cmd);
print "Content-type: text/plain\\n\\n$output";
''',
    # 11: system with interpolation
    '''\
use Mojolicious::Lite;
post '/archive' => sub {
    my $c = shift;
    my $dir = $c->param('directory');
    system("tar czf archive.tar.gz $dir");
    $c->render(text => 'Done');
};
app->start;
''',
    # 13: open pipe with interpolated path
    '''\
use Dancer2;
get '/log' => sub {
    my $logfile = params->{file};
    open(FH, "tail -100 $logfile |");
    my @lines = <FH>;
    close(FH);
    return join("\\n", @lines);
};
''',
    # 15: system with $variable direct
    '''\
use CGI;
my $q = CGI->new;
my $action = $q->param('action');
system($action);
print "Content-type: text/html\\n\\nDone";
''',
    # 17: backtick with Mojolicious param
    '''\
use Mojolicious::Lite;
get '/exec' => sub {
    my $c = shift;
    my $tool = $c->param('tool');
    my $result = `$tool --version`;
    $c->render(text => $result);
};
app->start;
''',
    # 19: system with interpolated string (Dancer2)
    '''\
use Dancer2;
post '/deploy' => sub {
    my $branch = params->{branch};
    system("git checkout $branch && make deploy");
    return { deployed => 1 };
};
''',
]

PERL_CMDI_SAFE = [
    # 2: system list form
    '''\
use CGI;
my $cgi = CGI->new;
my $host = $cgi->param('host');
system("ping", "-c", "4", $host);
''',
    # 4: IPC::Run
    '''\
use Mojolicious::Lite;
use IPC::Run qw(run);
get '/lookup' => sub {
    my $c = shift;
    my $domain = $c->param('domain');
    run(["nslookup", $domain], \\my $out, \\my $err);
    $c->render(text => $out);
};
app->start;
''',
    # 6: open with three-arg form and static command
    '''\
use CGI;
my $q = CGI->new;
my $file = $q->param('file');
open(my $fh, '<', "/var/data/$file");
my @lines = <$fh>;
close($fh);
print "Content-type: text/plain\\n\\n@lines";
''',
    # 8: exec list form (Dancer2)
    '''\
use Dancer2;
post '/convert' => sub {
    my $input = params->{filename};
    exec("convert", $input, "output.png");
};
''',
    # 10: hardcoded command
    '''\
use CGI;
my $cgi = CGI->new;
my $output = qx(ls /var/data);
print "Content-type: text/plain\\n\\n$output";
''',
    # 12: system list form (Mojolicious)
    '''\
use Mojolicious::Lite;
post '/archive' => sub {
    my $c = shift;
    my $dir = $c->param('directory');
    system("tar", "czf", "archive.tar.gz", $dir);
    $c->render(text => 'Done');
};
app->start;
''',
    # 14: open with three-arg safe form (Dancer2)
    '''\
use Dancer2;
get '/log' => sub {
    my $logfile = params->{file};
    open(my $fh, '<', "/var/log/$logfile");
    my @lines = <$fh>;
    close($fh);
    return join("\\n", @lines);
};
''',
    # 16: whitelisted commands
    '''\
use CGI;
my $q = CGI->new;
my $action = $q->param('action');
my %allowed = (status => 1, restart => 1, stop => 1);
if ($allowed{$action}) {
    system("systemctl", $action, "myservice");
}
print "Content-type: text/html\\n\\nDone";
''',
    # 18: static command (Mojolicious)
    '''\
use Mojolicious::Lite;
get '/version' => sub {
    my $c = shift;
    my $result = `git --version`;
    $c->render(text => $result);
};
app->start;
''',
    # 20: system list form (Dancer2)
    '''\
use Dancer2;
post '/deploy' => sub {
    my $branch = params->{branch};
    system("git", "checkout", $branch);
    system("make", "deploy");
    return { deployed => 1 };
};
''',
]

PERL_PATHTRAVER_VULN = [
    # 1: two-arg open with variable
    '''\
use CGI;
my $cgi = CGI->new;
my $file = $cgi->param('file');
open(FH, $file);
my @content = <FH>;
close(FH);
print "Content-type: text/plain\\n\\n@content";
''',
    # 3: three-arg open with user var
    '''\
use Mojolicious::Lite;
get '/download' => sub {
    my $c = shift;
    my $name = $c->param('name');
    open(my $fh, '<', $name);
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(data => $data);
};
app->start;
''',
    # 5: concat path with variable
    '''\
use CGI;
my $q = CGI->new;
my $doc = $q->param('doc');
open(my $fh, '<', "/var/uploads/" . $doc);
my @lines = <$fh>;
close($fh);
print "Content-type: text/plain\\n\\n@lines";
''',
    # 7: open for writing with var
    '''\
use Dancer2;
post '/save' => sub {
    my $filename = params->{filename};
    my $content = params->{content};
    open(my $fh, '>', $filename);
    print $fh $content;
    close($fh);
    return { saved => 1 };
};
''',
    # 9: three-arg open with user var (Mojolicious)
    '''\
use Mojolicious::Lite;
get '/view' => sub {
    my $c = shift;
    my $path = $c->param('path');
    open(my $fh, '<', $path);
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(text => $data);
};
app->start;
''',
    # 11: open with append mode
    '''\
use CGI;
my $cgi = CGI->new;
my $logfile = $cgi->param('logfile');
open(my $fh, '>>', $logfile);
print $fh "entry logged\\n";
close($fh);
print "Content-type: text/html\\n\\nLogged";
''',
    # 13: Dancer2 file read
    '''\
use Dancer2;
get '/template' => sub {
    my $tpl = params->{template};
    open(my $fh, '<', "/app/templates/" . $tpl);
    my $html = do { local $/; <$fh> };
    close($fh);
    return $html;
};
''',
    # 15: two-arg open (Mojolicious)
    '''\
use Mojolicious::Lite;
get '/raw' => sub {
    my $c = shift;
    my $f = $c->param('f');
    open(FH, $f);
    my @lines = <FH>;
    close(FH);
    $c->render(text => join('', @lines));
};
app->start;
''',
    # 17: open with user var direct
    '''\
use CGI;
my $q = CGI->new;
my $report = $q->param('report');
open(my $fh, '<', $report);
my $data = do { local $/; <$fh> };
close($fh);
print "Content-type: text/html\\n\\n$data";
''',
    # 19: open with variable (Dancer2)
    '''\
use Dancer2;
get '/config' => sub {
    my $file = params->{file};
    open(my $fh, '<', $file);
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
};
''',
]

PERL_PATHTRAVER_SAFE = [
    # 2: static file path (no user input)
    '''\
use CGI;
my $cgi = CGI->new;
open(my $fh, '<', '/var/data/readme.txt');
my @content = <$fh>;
close($fh);
print "Content-type: text/plain\\n\\n@content";
''',
    # 4: basename sanitization (Mojolicious)
    '''\
use Mojolicious::Lite;
use File::Basename;
get '/download' => sub {
    my $c = shift;
    my $name = basename($c->param('name'));
    open(my $fh, '<', "/var/uploads/$name");
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(data => $data);
};
app->start;
''',
    # 6: whitelist check
    '''\
use CGI;
my $q = CGI->new;
my $doc = $q->param('doc');
my %allowed = ('readme.txt' => 1, 'license.txt' => 1, 'changelog.txt' => 1);
die "Not allowed" unless $allowed{$doc};
open(my $fh, '<', "/var/uploads/$doc");
my @lines = <$fh>;
close($fh);
print "Content-type: text/plain\\n\\n@lines";
''',
    # 8: static filename (Dancer2)
    '''\
use Dancer2;
get '/readme' => sub {
    open(my $fh, '<', '/app/README.md');
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
};
''',
    # 10: hardcoded static path (Mojolicious)
    '''\
use Mojolicious::Lite;
get '/view' => sub {
    my $c = shift;
    open(my $fh, '<', '/var/www/index.html');
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(text => $data);
};
app->start;
''',
    # 12: basename + static dir
    '''\
use CGI;
use File::Basename;
my $cgi = CGI->new;
my $logfile = basename($cgi->param('logfile'));
open(my $fh, '>>', "/var/log/app/$logfile");
print $fh "entry logged\\n";
close($fh);
print "Content-type: text/html\\n\\nLogged";
''',
    # 14: hardcoded path (Dancer2)
    '''\
use Dancer2;
get '/template' => sub {
    open(my $fh, '<', '/app/templates/default.html');
    my $html = do { local $/; <$fh> };
    close($fh);
    return $html;
};
''',
    # 16: reject dotdot (Mojolicious)
    '''\
use Mojolicious::Lite;
get '/raw' => sub {
    my $c = shift;
    my $f = $c->param('f');
    return $c->render(text => 'Invalid', status => 400)
        if $f =~ /\\.\\./;
    open(my $fh, '<', "/var/data/$f");
    my @lines = <$fh>;
    close($fh);
    $c->render(text => join('', @lines));
};
app->start;
''',
    # 18: static path with hardcoded report name
    '''\
use CGI;
my $q = CGI->new;
open(my $fh, '<', '/reports/monthly_summary.csv');
my $data = do { local $/; <$fh> };
close($fh);
print "Content-type: text/html\\n\\n$data";
''',
    # 20: hardcoded config path (Dancer2)
    '''\
use Dancer2;
get '/config' => sub {
    open(my $fh, '<', '/app/config/settings.yml');
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
};
''',
]

PERL_XSS_VULN = [
    # 1: print param directly (CGI)
    '''\
use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('name');
print "Content-type: text/html\\n\\n";
print "<h1>Hello $name</h1>";
''',
    # 3: print $q->param (CGI shorthand)
    '''\
use CGI qw(:standard);
my $q = CGI->new;
my $input = $q->param('search');
print header();
print "<div>Results for: $input</div>";
''',
    # 5: CGI print with user var
    '''\
use CGI;
my $cgi = CGI->new;
my $user_input = $cgi->param('user');
print "Content-type: text/html\\n\\n";
print "<h1>Welcome $user_input</h1>";
''',
    # 7: CGI print param directly
    '''\
use CGI;
my $q = CGI->new;
print "Content-type: text/html\\n\\n";
print "<div class='profile'>" . $q->param('bio') . "</div>";
''',
    # 9: CGI direct print with variable
    '''\
use CGI;
my $cgi = CGI->new;
my $comment = $cgi->param('comment');
print "Content-type: text/html\\n\\n";
print "<div class='comment'>$comment</div>";
''',
    # 11: CGI print with $name variable
    '''\
use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('title');
print "Content-type: text/html\\n\\n";
print "<title>$name</title><body>Page</body>";
''',
    # 13: CGI print param in search results
    '''\
use CGI;
my $q = CGI->new;
my $query = $q->param('q');
print "Content-type: text/html\\n\\n";
print "<html><body>Search: $query</body></html>";
''',
    # 15: CGI print param in attribute
    '''\
use CGI;
my $q = CGI->new;
my $value = $q->param('value');
print "Content-type: text/html\\n\\n";
print "<input type='text' value='$value'>";
''',
    # 17: CGI print param in form
    '''\
use CGI;
my $cgi = CGI->new;
my $data = $cgi->param('default');
print "Content-type: text/html\\n\\n";
print "<form><input value='$data'></form>";
''',
    # 19: CGI print $content variable
    '''\
use CGI;
my $cgi = CGI->new;
my $content = $cgi->param('msg');
print "Content-type: text/html\\n\\n";
print "<div class='error'>$content</div>";
''',
]

PERL_XSS_SAFE = [
    # 2: HTML::Entities
    '''\
use CGI;
use HTML::Entities;
my $cgi = CGI->new;
my $name = $cgi->param('name');
my $safe = encode_entities($name);
print "Content-type: text/html\\n\\n";
print "<h1>Hello $safe</h1>";
''',
    # 4: CGI escapeHTML
    '''\
use CGI qw(:standard);
my $q = CGI->new;
my $input = $q->param('search');
my $safe = CGI::escapeHTML($input);
print header();
print "<div>Results for: $safe</div>";
''',
    # 6: Mojolicious with xml_escape
    '''\
use Mojolicious::Lite;
get '/greet' => sub {
    my $c = shift;
    my $user = $c->param('user');
    $c->render(text => "<h1>Welcome " . xml_escape($user) . "</h1>", format => 'html');
};
app->start;
''',
    # 8: Dancer2 with HTML::Entities
    '''\
use Dancer2;
use HTML::Entities;
get '/profile' => sub {
    my $bio = params->{bio};
    my $safe = encode_entities($bio);
    return "<div class='profile'>$safe</div>";
};
''',
    # 10: JSON output (not HTML)
    '''\
use CGI;
use JSON;
my $cgi = CGI->new;
my $comment = $cgi->param('comment');
print "Content-type: application/json\\n\\n";
print encode_json({ comment => $comment });
''',
    # 12: Mojolicious JSON render
    '''\
use Mojolicious::Lite;
get '/show' => sub {
    my $c = shift;
    my $title = $c->param('title');
    $c->render(json => { title => $title });
};
app->start;
''',
    # 14: Dancer2 with encode_entities
    '''\
use Dancer2;
use HTML::Entities;
get '/search' => sub {
    my $query = params->{q};
    my $safe = encode_entities($query);
    return "<html><body>Search: $safe</body></html>";
};
''',
    # 16: CGI with escapeHTML
    '''\
use CGI;
my $q = CGI->new;
my $value = $q->param('value');
my $safe = CGI::escapeHTML($value);
print "Content-type: text/html\\n\\n";
print "<input type='text' value='$safe'>";
''',
    # 18: Mojolicious JSON (not HTML)
    '''\
use Mojolicious::Lite;
get '/form' => sub {
    my $c = shift;
    my $default = $c->param('default');
    $c->render(json => { default_value => $default });
};
app->start;
''',
    # 20: Dancer2 template with auto-escape
    '''\
use Dancer2;
use HTML::Entities;
get '/error' => sub {
    my $msg = params->{msg};
    my $safe = encode_entities($msg);
    return "<div class='error'>$safe</div>";
};
''',
]

# ============================================================================
# LUA fixtures (60 cases: 3 categories x 20 each)
# ============================================================================

LUA_SQLI_VULN = [
    # 1: string concat in query
    '''\
local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local name = args.name
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="app"})
local res = db:query("SELECT * FROM users WHERE name = '" .. name .. "'")
ngx.say(res)
''',
    # 3: string.format with SELECT
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local id = args.id
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
local query = string.format("SELECT * FROM orders WHERE id = %s", id)
local res = pg:query(query)
ngx.say(res)
''',
    # 5: concat in DELETE
    '''\
local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local item_id = args.item_id
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="shop"})
db:query("DELETE FROM items WHERE id = " .. item_id)
ngx.say("deleted")
''',
    # 7: concat in UPDATE
    '''\
local mysql = require "resty.mysql"
local args = ngx.req.get_post_args()
local status = args.status
local oid = args.order_id
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="store"})
db:query("UPDATE orders SET status = '" .. status .. "' WHERE id = " .. oid)
ngx.say("updated")
''',
    # 9: string.format in INSERT
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_post_args()
local username = args.username
local email = args.email
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
local q = string.format("INSERT INTO users (name, email) VALUES ('%s', '%s')", username, email)
pg:query(q)
ngx.say("created")
''',
    # 11: concat with LIKE
    '''\
local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local search = args.q
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="blog"})
local res = db:query("SELECT * FROM posts WHERE title LIKE '%" .. search .. "%'")
ngx.say(res)
''',
    # 13: concat in subquery
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local dept = args.department
local pg = pgmoon.new({host="127.0.0.1", database="hr"})
pg:connect()
local res = pg:query("SELECT * FROM employees WHERE dept_id = " .. dept)
ngx.say(res)
''',
    # 15: string.format DROP (injection test)
    '''\
local mysql = require "resty.mysql"
local args = ngx.req.get_uri_args()
local table_name = args.table
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="admin"})
local q = string.format("SELECT COUNT(*) FROM %s", table_name)
local res = db:query(q)
ngx.say(res)
''',
    # 17: concat in JOIN query
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local user_id = args.uid
local pg = pgmoon.new({host="127.0.0.1", database="social"})
pg:connect()
local res = pg:query("SELECT p.* FROM posts p JOIN users u ON p.user_id = u.id WHERE u.id = " .. user_id)
ngx.say(res)
''',
    # 19: concat in auth query
    '''\
local mysql = require "resty.mysql"
local args = ngx.req.get_post_args()
local user = args.username
local pass = args.password
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="auth"})
local res = db:query("SELECT * FROM accounts WHERE username = '" .. user .. "' AND password = '" .. pass .. "'")
ngx.say(res)
''',
]

LUA_SQLI_SAFE = [
    # 2: pgmoon parameterized query
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local name = args.name
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
local res = pg:query("SELECT * FROM users WHERE name = $1", name)
ngx.say(res)
''',
    # 4: pgmoon parameterized query
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local id = args.id
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
local res = pg:query("SELECT * FROM orders WHERE id = $1", id)
ngx.say(res)
''',
    # 6: hardcoded DELETE
    '''\
local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="shop"})
db:query("DELETE FROM items WHERE id = 42")
ngx.say("deleted")
''',
    # 8: hardcoded UPDATE
    '''\
local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="store"})
db:query("UPDATE orders SET status = 'shipped' WHERE id = 100")
ngx.say("updated")
''',
    # 10: pgmoon parameterized insert
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_post_args()
local username = args.username
local email = args.email
local pg = pgmoon.new({host="127.0.0.1", database="app"})
pg:connect()
pg:query("INSERT INTO users (name, email) VALUES ($1, $2)", username, email)
ngx.say("created")
''',
    # 12: hardcoded LIKE query
    '''\
local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="blog"})
local res = db:query("SELECT * FROM posts WHERE title LIKE '%news%'")
ngx.say(res)
''',
    # 14: pgmoon parameterized department
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local dept = args.department
local pg = pgmoon.new({host="127.0.0.1", database="hr"})
pg:connect()
local res = pg:query("SELECT * FROM employees WHERE dept_id = $1", dept)
ngx.say(res)
''',
    # 16: hardcoded table name
    '''\
local mysql = require "resty.mysql"
local db = mysql:new()
db:connect({host="127.0.0.1", port=3306, database="admin"})
local res = db:query("SELECT COUNT(*) FROM users")
ngx.say(res)
''',
    # 18: pgmoon parameterized JOIN
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_uri_args()
local user_id = args.uid
local pg = pgmoon.new({host="127.0.0.1", database="social"})
pg:connect()
local res = pg:query("SELECT p.* FROM posts p JOIN users u ON p.user_id = u.id WHERE u.id = $1", user_id)
ngx.say(res)
''',
    # 20: pgmoon parameterized auth
    '''\
local pgmoon = require "pgmoon"
local args = ngx.req.get_post_args()
local user = args.username
local pass = args.password
local pg = pgmoon.new({host="127.0.0.1", database="auth"})
pg:connect()
local res = pg:query("SELECT * FROM accounts WHERE username = $1 AND password = $2", user, pass)
ngx.say(res)
''',
]

LUA_CMDI_VULN = [
    # 1: os.execute with concat
    '''\
local args = ngx.req.get_uri_args()
local host = args.host
os.execute("ping -c 4 " .. host)
ngx.say("done")
''',
    # 3: io.popen with concat
    '''\
local args = ngx.req.get_uri_args()
local domain = args.domain
local handle = io.popen("nslookup " .. domain)
local result = handle:read("*a")
handle:close()
ngx.say(result)
''',
    # 5: os.execute with format
    '''\
local args = ngx.req.get_uri_args()
local filename = args.file
os.execute("cat " .. filename)
ngx.say("done")
''',
    # 7: io.popen with variable
    '''\
local args = ngx.req.get_post_args()
local cmd = args.command
local handle = io.popen(cmd)
local output = handle:read("*a")
handle:close()
ngx.say(output)
''',
    # 9: os.execute with user input
    '''\
local args = ngx.req.get_uri_args()
local target = args.target
os.execute("traceroute " .. target)
ngx.say("trace complete")
''',
    # 11: io.popen for file listing
    '''\
local args = ngx.req.get_uri_args()
local dir = args.dir
local handle = io.popen("ls -la " .. dir)
local result = handle:read("*a")
handle:close()
ngx.say(result)
''',
    # 13: os.execute in conversion
    '''\
local args = ngx.req.get_post_args()
local input_file = args.input
os.execute("convert " .. input_file .. " output.png")
ngx.say("converted")
''',
    # 15: io.popen with grep
    '''\
local args = ngx.req.get_uri_args()
local pattern = args.pattern
local handle = io.popen("grep -r " .. pattern .. " /var/log/")
local result = handle:read("*a")
handle:close()
ngx.say(result)
''',
    # 17: os.execute with tar
    '''\
local args = ngx.req.get_post_args()
local archive_name = args.name
os.execute("tar czf /tmp/" .. archive_name .. ".tar.gz /var/data/")
ngx.say("archived")
''',
    # 19: io.popen with curl
    '''\
local args = ngx.req.get_uri_args()
local url = args.url
local handle = io.popen("curl -s " .. url)
local body = handle:read("*a")
handle:close()
ngx.say(body)
''',
]

LUA_CMDI_SAFE = [
    # 2: hardcoded command
    '''\
local args = ngx.req.get_uri_args()
os.execute("ping -c 4 localhost")
ngx.say("done")
''',
    # 4: ngx.socket.tcp instead of popen
    '''\
local args = ngx.req.get_uri_args()
local domain = args.domain
local resolver = require "resty.dns.resolver"
local r = resolver:new({nameservers = {"8.8.8.8"}})
local answers = r:query(domain)
ngx.say(answers)
''',
    # 6: validated filename
    '''\
local args = ngx.req.get_uri_args()
local filename = args.file
if not filename:match("^[%w%.%-_]+$") then
    ngx.exit(400)
end
local f = io.open("/var/data/" .. filename, "r")
local content = f:read("*a")
f:close()
ngx.say(content)
''',
    # 8: hardcoded command
    '''\
local args = ngx.req.get_post_args()
os.execute("myapp status")
ngx.say("done")
''',
    # 10: static command
    '''\
local args = ngx.req.get_uri_args()
os.execute("traceroute 8.8.8.8")
ngx.say("trace complete")
''',
    # 12: resty.shell with args table
    '''\
local shell = require "resty.shell"
local args = ngx.req.get_uri_args()
local dir = args.dir
if not dir:match("^[%w/%-_]+$") then
    ngx.exit(400)
end
local ok, stdout = shell.run("ls", {"-la", dir})
ngx.say(stdout)
''',
    # 14: hardcoded convert command
    '''\
local args = ngx.req.get_post_args()
os.execute("convert /uploads/photo.jpg /output/photo.png")
ngx.say("converted")
''',
    # 16: hardcoded grep
    '''\
local args = ngx.req.get_uri_args()
local handle = io.popen("grep -r 'ERROR' /var/log/app.log")
local result = handle:read("*a")
handle:close()
ngx.say(result)
''',
    # 18: static tar command
    '''\
local args = ngx.req.get_post_args()
os.execute("tar czf /tmp/backup.tar.gz /var/data/")
ngx.say("archived")
''',
    # 20: resty.http instead of curl
    '''\
local http = require "resty.http"
local args = ngx.req.get_uri_args()
local url = args.url
local httpc = http.new()
local res = httpc:request_uri(url, {method = "GET"})
ngx.say(res.body)
''',
]

LUA_XSS_VULN = [
    # 1: ngx.say with user input
    '''\
local args = ngx.req.get_uri_args()
local name = args.name
ngx.say("<h1>Hello " .. name .. "</h1>")
''',
    # 3: ngx.print with variable
    '''\
local args = ngx.req.get_uri_args()
local message = args.msg
ngx.print("<div>" .. message .. "</div>")
''',
    # 5: ngx.say with direct variable
    '''\
local args = ngx.req.get_uri_args()
local search = args.q
ngx.say(search)
''',
    # 7: ngx.say with body data
    '''\
ngx.req.read_body()
local body = ngx.req.get_body_data()
ngx.say("<pre>" .. body .. "</pre>")
''',
    # 9: ngx.print with post args
    '''\
ngx.req.read_body()
local args = ngx.req.get_post_args()
local comment = args.comment
ngx.print("<p>" .. comment .. "</p>")
''',
    # 11: ngx.say with attribute injection
    '''\
local args = ngx.req.get_uri_args()
local value = args.value
ngx.say("<input type='text' value='" .. value .. "'>")
''',
    # 13: ngx.print with multiple vars
    '''\
local args = ngx.req.get_uri_args()
local title = args.title
local desc = args.desc
ngx.print("<h1>" .. title .. "</h1><p>" .. desc .. "</p>")
''',
    # 15: ngx.say with ngx.var
    '''\
local user_agent = ngx.var.http_user_agent
ngx.say("<p>Your browser: " .. user_agent .. "</p>")
''',
    # 17: ngx.say with cookie
    '''\
local cookie = ngx.var.cookie_username
ngx.say("<span>Welcome back, " .. cookie .. "</span>")
''',
    # 19: ngx.print in error page
    '''\
local args = ngx.req.get_uri_args()
local error_msg = args.error
ngx.print("<div class='error'>" .. error_msg .. "</div>")
''',
]

LUA_XSS_SAFE = [
    # 2: ngx.escape_uri
    '''\
local args = ngx.req.get_uri_args()
local name = args.name
ngx.say("<h1>Hello " .. ngx.escape_uri(name) .. "</h1>")
''',
    # 4: html_escape function
    '''\
local function html_escape(s)
    return s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;"):gsub("'", "&#39;")
end
local args = ngx.req.get_uri_args()
local message = args.msg
ngx.print("<div>" .. html_escape(message) .. "</div>")
''',
    # 6: JSON response (not HTML)
    '''\
local cjson = require "cjson"
local args = ngx.req.get_uri_args()
local search = args.q
ngx.header.content_type = "application/json"
ngx.say(cjson.encode({query = search}))
''',
    # 8: template.escape
    '''\
local template = require "resty.template"
ngx.req.read_body()
local body = ngx.req.get_body_data()
ngx.say("<pre>" .. template.escape(body) .. "</pre>")
''',
    # 10: html_escape function with post args
    '''\
local function html_escape(s)
    return s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
end
ngx.req.read_body()
local args = ngx.req.get_post_args()
local comment = args.comment
ngx.print("<p>" .. html_escape(comment) .. "</p>")
''',
    # 12: ngx.escape_uri for attribute
    '''\
local args = ngx.req.get_uri_args()
local value = args.value
ngx.say("<input type='text' value='" .. ngx.escape_uri(value) .. "'>")
''',
    # 14: JSON output
    '''\
local cjson = require "cjson"
local args = ngx.req.get_uri_args()
local title = args.title
local desc = args.desc
ngx.header.content_type = "application/json"
ngx.say(cjson.encode({title = title, description = desc}))
''',
    # 16: static content (no user input in output)
    '''\
local user_agent = ngx.var.http_user_agent
ngx.log(ngx.INFO, "UA: " .. user_agent)
ngx.say("<p>Your browser info has been logged.</p>")
''',
    # 18: html_escape cookie
    '''\
local function html_escape(s)
    if not s then return "" end
    return s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;")
end
local cookie = ngx.var.cookie_username
ngx.say("<span>Welcome back, " .. html_escape(cookie) .. "</span>")
''',
    # 20: ngx.escape_uri error message
    '''\
local args = ngx.req.get_uri_args()
local error_msg = args.error
ngx.print("<div class='error'>" .. ngx.escape_uri(error_msg) .. "</div>")
''',
]

# ============================================================================
# GROOVY fixtures (80 cases: 4 categories x 20 each)
# ============================================================================

GROOVY_SQLI_VULN = [
    # 1: GString in sql.execute
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/app", "root", "", "com.mysql.jdbc.Driver")
def name = params.name
sql.execute("SELECT * FROM users WHERE name = '${name}'")
''',
    # 3: GString in sql.rows
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:h2:mem:test")
def category = request.getParameter("category")
def results = sql.rows("SELECT * FROM products WHERE category = '${category}'")
''',
    # 5: GString in sql.firstRow (Grails)
    '''\
class UserController {
    def dataSource
    def show() {
        def sql = new groovy.sql.Sql(dataSource)
        def id = params.id
        def user = sql.firstRow("SELECT * FROM users WHERE id = ${id}")
        render user as JSON
    }
}
''',
    # 7: GString in sql.eachRow
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:postgresql://localhost/app")
def dept = request.getParameter("department")
sql.eachRow("SELECT * FROM employees WHERE dept = '${dept}'") { row ->
    println row.name
}
''',
    # 9: GString in executeUpdate
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/shop")
def status = params.status
def orderId = params.order_id
sql.executeUpdate("UPDATE orders SET status = '${status}' WHERE id = ${orderId}")
''',
    # 11: concat in sql.execute
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:h2:mem:test")
def search = request.getParameter("q")
def results = sql.rows("SELECT * FROM items WHERE title LIKE '%" + search + "%'")
''',
    # 13: GString in execute (Jenkins pipeline)
    '''\
def call(Map config) {
    def dbName = config.database
    def sql = Sql.newInstance("jdbc:mysql://db:3306/${dbName}")
    def table = config.table
    sql.execute("SELECT COUNT(*) FROM ${table}")
}
''',
    # 15: concat in firstRow
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/auth")
def username = params.username
def password = params.password
def user = sql.firstRow("SELECT * FROM accounts WHERE user = '" + username + "' AND pass = '" + password + "'")
''',
    # 17: GString in delete (Grails)
    '''\
class AdminController {
    def dataSource
    def deleteItem() {
        def sql = new groovy.sql.Sql(dataSource)
        def itemId = params.itemId
        sql.execute("DELETE FROM items WHERE id = ${itemId}")
        redirect(action: "list")
    }
}
''',
    # 19: GString in INSERT
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:postgresql://localhost/blog")
def title = params.title
def body = params.body
sql.execute("INSERT INTO posts (title, body) VALUES ('${title}', '${body}')")
''',
]

GROOVY_SQLI_SAFE = [
    # 2: Parameterized query with list
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/app", "root", "", "com.mysql.jdbc.Driver")
def name = params.name
sql.execute("SELECT * FROM users WHERE name = ?", [name])
''',
    # 4: Parameterized rows
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:h2:mem:test")
def category = request.getParameter("category")
def results = sql.rows("SELECT * FROM products WHERE category = ?", [category])
''',
    # 6: Parameterized firstRow (Grails)
    '''\
class UserController {
    def dataSource
    def show() {
        def sql = new groovy.sql.Sql(dataSource)
        def id = params.id
        def user = sql.firstRow("SELECT * FROM users WHERE id = ?", [id])
        render user as JSON
    }
}
''',
    # 8: Parameterized eachRow
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:postgresql://localhost/app")
def dept = request.getParameter("department")
sql.eachRow("SELECT * FROM employees WHERE dept = ?", [dept]) { row ->
    println row.name
}
''',
    # 10: Parameterized executeUpdate
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/shop")
def status = params.status
def orderId = params.order_id
sql.executeUpdate("UPDATE orders SET status = ? WHERE id = ?", [status, orderId])
''',
    # 12: Parameterized LIKE
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:h2:mem:test")
def search = request.getParameter("q")
def results = sql.rows("SELECT * FROM items WHERE title LIKE ?", ["%" + search + "%"])
''',
    # 14: hardcoded query
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/admin")
def results = sql.rows("SELECT COUNT(*) FROM users")
''',
    # 16: Parameterized auth query
    '''\
import groovy.sql.Sql

def sql = Sql.newInstance("jdbc:mysql://localhost/auth")
def username = params.username
def password = params.password
def user = sql.firstRow("SELECT * FROM accounts WHERE user = ? AND pass = ?", [username, password])
''',
    # 18: GORM criteria (Grails)
    '''\
class AdminController {
    def deleteItem() {
        def itemId = params.itemId?.toLong()
        if (itemId) {
            Item.get(itemId)?.delete()
        }
        redirect(action: "list")
    }
}
''',
    # 20: GORM save (Grails)
    '''\
class PostController {
    def save() {
        def post = new Post(title: params.title, body: params.body)
        post.save(flush: true)
        redirect(action: "show", id: post.id)
    }
}
''',
]

GROOVY_CMDI_VULN = [
    # 1: GString .execute()
    '''\
def host = params.host
"ping -c 4 ${host}".execute()
''',
    # 3: GString .execute() with nslookup
    '''\
def domain = request.getParameter("domain")
"nslookup ${domain}".execute()
''',
    # 5: GString .execute() with git (Jenkins)
    '''\
node {
    def branch = params.BRANCH
    "git checkout ${branch}".execute()
}
''',
    # 7: GString .execute() with curl
    '''\
def url = params.url
"curl -s ${url}".execute()
''',
    # 9: GString in sh step (Jenkins)
    '''\
pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                script {
                    def target = params.TARGET
                    sh "deploy.sh ${target}"
                }
            }
        }
    }
}
''',
    # 11: GString .execute() with docker (Jenkins)
    '''\
node {
    def version = params.VERSION
    "docker build -t myapp:${version} .".execute()
}
''',
    # 13: GString .execute() with cat
    '''\
def filename = request.getParameter("file")
"cat /var/data/${filename}".execute()
''',
    # 15: GString in bat step (Jenkins)
    '''\
pipeline {
    agent { label 'windows' }
    stages {
        stage('Build') {
            steps {
                script {
                    def config = params.CONFIG
                    bat "msbuild /p:Configuration=${config}"
                }
            }
        }
    }
}
''',
    # 17: GString .execute() with which
    '''\
def tool = params.tool
"which ${tool}".execute()
''',
    # 19: GString in sh (Jenkins)
    '''\
node {
    def url = params.WEBHOOK_URL
    sh "curl -X POST ${url}"
}
''',
]

GROOVY_CMDI_SAFE = [
    # 2: hardcoded command string
    '''\
def result = "ping -c 4 localhost".execute()
println result.text
''',
    # 4: static nslookup
    '''\
def result = "nslookup example.com".execute()
println result.text
''',
    # 6: static command (Jenkins)
    '''\
node {
    sh "git status"
}
''',
    # 8: hardcoded curl
    '''\
def result = "curl -s https://api.example.com/health".execute()
println result.text
''',
    # 10: single-quoted sh step (Jenkins)
    '''\
pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                sh 'deploy.sh production'
            }
        }
    }
}
''',
    # 12: static docker command
    '''\
def result = "docker ps".execute()
println result.text
''',
    # 14: hardcoded cat
    '''\
def result = "cat /var/data/config.yml".execute()
println result.text
''',
    # 16: static bat step (Jenkins)
    '''\
pipeline {
    agent { label 'windows' }
    stages {
        stage('Build') {
            steps {
                bat 'msbuild /p:Configuration=Release'
            }
        }
    }
}
''',
    # 18: hardcoded which
    '''\
def result = "which java".execute()
println result.text
''',
    # 20: credentials binding (Jenkins)
    '''\
node {
    withCredentials([string(credentialsId: 'webhook', variable: 'URL')]) {
        sh 'curl -X POST $URL'
    }
}
''',
]

GROOVY_XSS_VULN = [
    # 1: GroovyShell.evaluate with user input
    '''\
class ScriptController {
    def run() {
        def code = params.code
        def shell = new GroovyShell()
        def result = shell.evaluate(code)
        render result.toString()
    }
}
''',
    # 3: GroovyShell.evaluate with request param
    '''\
class CalcController {
    def calculate() {
        def expr = request.getParameter("expression")
        def result = new GroovyShell().evaluate(expr)
        render result.toString()
    }
}
''',
    # 5: Eval.me with user input
    '''\
class TemplateController {
    def render() {
        def template = params.template
        def output = Eval.me(template)
        render output.toString()
    }
}
''',
    # 7: GroovyShell.parse with param
    '''\
class PluginController {
    def load() {
        def script = params.script
        def shell = new GroovyShell()
        def parsed = shell.parse(script)
        parsed.run()
    }
}
''',
    # 9: Eval.me in data processor
    '''\
class DataController {
    def transform() {
        def rule = params.transform_rule
        def data = params.data
        def result = Eval.me("data", data, rule)
        render result
    }
}
''',
    # 11: GroovyScriptEngine.run
    '''\
class RunController {
    def execute() {
        def scriptName = params.script
        def engine = new GroovyScriptEngine("scripts/")
        engine.run(scriptName, new Binding())
    }
}
''',
    # 13: ScriptEngine eval
    '''\
import javax.script.ScriptEngineManager

class EvalController {
    def run() {
        def code = params.code
        def engine = new ScriptEngineManager().getEngineByName("groovy")
        def result = engine.eval(code)
        render result.toString()
    }
}
''',
    # 15: GroovyShell.evaluate from POST body
    '''\
class APIController {
    def execute() {
        def body = request.reader.text
        def shell = new GroovyShell()
        def result = shell.evaluate(body)
        render result
    }
}
''',
    # 17: Eval.x with param
    '''\
class FilterController {
    def apply() {
        def filter = params.filter
        def items = [1, 2, 3, 4, 5]
        def result = Eval.x(items, filter)
        render result.toString()
    }
}
''',
    # 19: GroovyShell in pipeline
    '''\
def call(Map config) {
    def code = config.customScript
    def shell = new GroovyShell()
    shell.evaluate(code)
}
''',
]

GROOVY_XSS_SAFE = [
    # 2: JsonSlurper (safe parsing)
    '''\
import groovy.json.JsonSlurper

class ScriptController {
    def run() {
        def code = params.code
        def slurper = new JsonSlurper()
        def result = slurper.parseText(code)
        render result.toString()
    }
}
''',
    # 4: static expression
    '''\
class CalcController {
    def calculate() {
        def a = params.a?.toInteger() ?: 0
        def b = params.b?.toInteger() ?: 0
        def result = a + b
        render result.toString()
    }
}
''',
    # 6: template engine with sandbox
    '''\
import groovy.text.SimpleTemplateEngine

class TemplateController {
    def render() {
        def name = params.name
        def engine = new SimpleTemplateEngine()
        def template = engine.createTemplate('Hello ${name}')
        render template.make([name: name]).toString()
    }
}
''',
    # 8: direct method call (no shell)
    '''\
class PluginController {
    def load() {
        def name = params.name
        def result = "Hello, " + name.replaceAll("[^a-zA-Z]", "")
        render result
    }
}
''',
    # 10: map-based dispatch
    '''\
class DataController {
    def transform() {
        def rule = params.transform_rule
        def data = params.data
        def transforms = [upper: { it.toUpperCase() }, lower: { it.toLowerCase() }]
        def fn = transforms[rule]
        def result = fn ? fn(data) : data
        render result
    }
}
''',
    # 12: direct computation (no shell)
    '''\
class RunController {
    def execute() {
        def a = params.a?.toDouble() ?: 0
        def b = params.b?.toDouble() ?: 0
        def result = a * b
        render result.toString()
    }
}
''',
    # 14: static version string (no eval)
    '''\
class EvalController {
    def version() {
        def result = GroovySystem.version
        render "Groovy version: ${result}"
    }
}
''',
    # 16: JsonSlurper from POST body
    '''\
import groovy.json.JsonSlurper

class APIController {
    def execute() {
        def body = request.reader.text
        def data = new JsonSlurper().parseText(body)
        render data.toString()
    }
}
''',
    # 18: whitelist filter
    '''\
class FilterController {
    def apply() {
        def filter = params.filter
        def allowed = ["even", "odd", "positive"]
        if (!(filter in allowed)) {
            render "Invalid filter"
            return
        }
        render "Applied: ${filter}"
    }
}
''',
    # 20: println in pipeline (no eval)
    '''\
def call(Map config) {
    println "Build started for ${config.project}"
}
''',
]

GROOVY_DESER_VULN = [
    # 1: ObjectInputStream.readObject
    '''\
import java.io.*

def data = request.inputStream
def ois = new ObjectInputStream(data)
def obj = ois.readObject()
ois.close()
''',
    # 3: XStream fromXML
    '''\
import com.thoughtworks.xstream.XStream

def xml = request.getParameter("data")
def xstream = new XStream()
def obj = xstream.fromXML(xml)
''',
    # 5: SnakeYAML load (Jenkins)
    '''\
import org.yaml.snakeyaml.Yaml

node {
    def content = readFile('config.yaml')
    def yaml = new Yaml()
    def config = yaml.load(content)
}
''',
    # 7: ObjectInputStream from socket
    '''\
import java.io.*
import java.net.*

def server = new ServerSocket(9090)
def client = server.accept()
def ois = new ObjectInputStream(client.inputStream)
def message = ois.readObject()
''',
    # 9: XStream from POST body
    '''\
import com.thoughtworks.xstream.XStream

class ImportController {
    def importData() {
        def body = request.reader.text
        def xstream = new XStream()
        def data = xstream.fromXML(body)
        render "Imported ${data.size()} records"
    }
}
''',
    # 11: SnakeYAML with user input
    '''\
import org.yaml.snakeyaml.Yaml

class ConfigController {
    def upload() {
        def content = params.yaml_content
        def yaml = new Yaml()
        def config = yaml.load(content)
        render config as JSON
    }
}
''',
    # 13: ObjectInputStream from file param
    '''\
import java.io.*

class DataController {
    def load() {
        def file = params.file
        def fis = new FileInputStream(file)
        def ois = new ObjectInputStream(fis)
        def obj = ois.readObject()
        ois.close()
        render obj.toString()
    }
}
''',
    # 15: XStream in pipeline (Jenkins)
    '''\
import com.thoughtworks.xstream.XStream

node {
    def xml = readFile('data.xml')
    def xstream = new XStream()
    def config = xstream.fromXML(xml)
    echo "Loaded: ${config}"
}
''',
    # 17: Yaml.load from URL
    '''\
import org.yaml.snakeyaml.Yaml

def url = params.config_url
def content = new URL(url).text
def yaml = new Yaml()
def config = yaml.load(content)
''',
    # 19: ObjectInputStream with Base64
    '''\
import java.io.*

class SessionController {
    def restore() {
        def encoded = params.session_data
        def bytes = encoded.decodeBase64()
        def ois = new ObjectInputStream(new ByteArrayInputStream(bytes))
        def session = ois.readObject()
        render session.toString()
    }
}
''',
]

GROOVY_DESER_SAFE = [
    # 2: JsonSlurper
    '''\
import groovy.json.JsonSlurper

def data = request.reader.text
def slurper = new JsonSlurper()
def obj = slurper.parseText(data)
''',
    # 4: XmlSlurper with secure features
    '''\
import javax.xml.parsers.SAXParserFactory

def xml = request.getParameter("data")
def factory = SAXParserFactory.newInstance()
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
def slurper = new XmlSlurper(factory.newSAXParser())
def obj = slurper.parseText(xml)
''',
    # 6: Yaml safe constructor (Jenkins)
    '''\
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

node {
    def content = readFile('config.yaml')
    def yaml = new Yaml(new SafeConstructor())
    def config = yaml.load(content)
}
''',
    # 8: JsonSlurper from socket
    '''\
import groovy.json.JsonSlurper
import java.net.*

def server = new ServerSocket(9090)
def client = server.accept()
def reader = new BufferedReader(new InputStreamReader(client.inputStream))
def json = reader.readLine()
def message = new JsonSlurper().parseText(json)
''',
    # 10: JSON parse (Grails)
    '''\
import groovy.json.JsonSlurper

class ImportController {
    def importData() {
        def body = request.reader.text
        def data = new JsonSlurper().parseText(body)
        render "Imported ${data.size()} records"
    }
}
''',
    # 12: Yaml SafeConstructor with user input
    '''\
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

class ConfigController {
    def upload() {
        def content = params.yaml_content
        def yaml = new Yaml(new SafeConstructor())
        def config = yaml.load(content)
        render config as JSON
    }
}
''',
    # 14: JsonSlurper from file
    '''\
import groovy.json.JsonSlurper

class DataController {
    def load() {
        def file = params.file
        def content = new File("/app/data/${file}").text
        def obj = new JsonSlurper().parseText(content)
        render obj.toString()
    }
}
''',
    # 16: JsonSlurper in pipeline (Jenkins)
    '''\
import groovy.json.JsonSlurper

node {
    def json = readFile('data.json')
    def config = new JsonSlurper().parseText(json)
    echo "Loaded: ${config}"
}
''',
    # 18: safe URL fetch + JSON parse
    '''\
import groovy.json.JsonSlurper

def url = params.config_url
def content = new URL(url).text
def config = new JsonSlurper().parseText(content)
''',
    # 20: JsonSlurper for session data
    '''\
import groovy.json.JsonSlurper

class SessionController {
    def restore() {
        def encoded = params.session_data
        def json = new String(encoded.decodeBase64())
        def session = new JsonSlurper().parseText(json)
        render session.toString()
    }
}
''',
]


def write_bench(lang, ext, categories, output_dir):
    """Write benchmark fixture files and expectedresults.csv."""
    os.makedirs(output_dir, exist_ok=True)
    csv_lines = []
    file_num = 0

    for cat_name, cwe, vuln_list, safe_list in categories:
        for i in range(10):
            # Vulnerable case
            file_num += 1
            fname = f"BenchmarkTest{file_num:05d}{ext}"
            with open(os.path.join(output_dir, fname), 'w') as f:
                f.write(vuln_list[i])
            csv_lines.append(f"BenchmarkTest{file_num:05d},{cat_name},true,{cwe}")

            # Safe case
            file_num += 1
            fname = f"BenchmarkTest{file_num:05d}{ext}"
            with open(os.path.join(output_dir, fname), 'w') as f:
                f.write(safe_list[i])
            csv_lines.append(f"BenchmarkTest{file_num:05d},{cat_name},false,{cwe}")

    with open(os.path.join(output_dir, "expectedresults.csv"), 'w') as f:
        f.write('\n'.join(csv_lines) + '\n')

    print(f"  {lang}: wrote {file_num} fixtures + expectedresults.csv to {output_dir}")


def main():
    bench_dir = os.path.join(ROOT, "testdata", "bench")

    print("Generating OWASP-style benchmark fixtures...")

    write_bench("perl", ".pl", [
        ("sqli", "89", PERL_SQLI_VULN, PERL_SQLI_SAFE),
        ("cmdi", "78", PERL_CMDI_VULN, PERL_CMDI_SAFE),
        ("pathtraver", "22", PERL_PATHTRAVER_VULN, PERL_PATHTRAVER_SAFE),
        ("xss", "79", PERL_XSS_VULN, PERL_XSS_SAFE),
    ], os.path.join(bench_dir, "perl"))

    write_bench("lua", ".lua", [
        ("sqli", "89", LUA_SQLI_VULN, LUA_SQLI_SAFE),
        ("cmdi", "78", LUA_CMDI_VULN, LUA_CMDI_SAFE),
        ("xss", "79", LUA_XSS_VULN, LUA_XSS_SAFE),
    ], os.path.join(bench_dir, "lua"))

    write_bench("groovy", ".groovy", [
        ("sqli", "89", GROOVY_SQLI_VULN, GROOVY_SQLI_SAFE),
        ("cmdi", "78", GROOVY_CMDI_VULN, GROOVY_CMDI_SAFE),
        ("codeinj", "94", GROOVY_XSS_VULN, GROOVY_XSS_SAFE),
        ("deser", "502", GROOVY_DESER_VULN, GROOVY_DESER_SAFE),
    ], os.path.join(bench_dir, "groovy"))

    print("Done!")


if __name__ == "__main__":
    main()
