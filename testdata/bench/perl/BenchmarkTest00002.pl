use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('name');
my $dbh = DBI->connect("dbi:mysql:testdb", "root", "");
my $sth = $dbh->prepare("SELECT * FROM users WHERE name = ?");
$sth->execute($name);
