use CGI;
my $cgi = CGI->new;
my $data = $cgi->param('default');
print "Content-type: text/html\n\n";
print "<form><input value='$data'></form>";
