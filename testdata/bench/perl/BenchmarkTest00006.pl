use CGI;
my $q = CGI->new;
my $id = $q->param('id');
my $dbh = DBI->connect("dbi:mysql:app", "user", "pass");
my $row = $dbh->selectrow_arrayref("SELECT * FROM orders WHERE id = ?", undef, $id);
print "Content-type: text/html\n\n";
print $row->[1];
