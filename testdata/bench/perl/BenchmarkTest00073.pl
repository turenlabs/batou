use CGI;
my $q = CGI->new;
my $query = $q->param('q');
print "Content-type: text/html\n\n";
print "<html><body>Search: $query</body></html>";
