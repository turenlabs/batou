use CGI;
my $q = CGI->new;
my $dbh = DBI->connect("dbi:mysql:analytics");
my $count = $dbh->selectrow_arrayref("SELECT COUNT(*) FROM page_views");
print "Content-type: text/html\n\n$count->[0]";
