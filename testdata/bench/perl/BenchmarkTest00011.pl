use CGI;
my $cgi = CGI->new;
my $dept = $cgi->param('department');
my $dbh = DBI->connect("dbi:Pg:dbname=hr", "admin", "secret");
my $rows = $dbh->selectall_arrayref("SELECT name, salary FROM employees WHERE dept = '$dept'");
