use CGI;
my $cgi = CGI->new;
my $user_input = $cgi->param('user');
print "Content-type: text/html\n\n";
print "<h1>Welcome $user_input</h1>";
