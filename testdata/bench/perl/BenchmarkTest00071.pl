use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('title');
print "Content-type: text/html\n\n";
print "<title>$name</title><body>Page</body>";
