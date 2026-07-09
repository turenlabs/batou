use CGI;
my $q = CGI->new;
my $table = $q->param('table');
my $dbh = DBI->connect("dbi:mysql:analytics");
my $count = $dbh->selectrow_arrayref("SELECT COUNT(*) FROM $table");
print "Content-type: text/html\n\n$count->[0]";
