use CGI;
my $cgi = CGI->new;
my $name = $cgi->param('name');
print "Content-type: text/html\n\n";
print "<h1>Hello $name</h1>";
