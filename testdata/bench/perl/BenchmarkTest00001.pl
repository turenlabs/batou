use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('name');
my $dbh = DBI->connect("dbi:mysql:testdb", "root", "");
$dbh->do("SELECT * FROM users WHERE name = '$name'");
