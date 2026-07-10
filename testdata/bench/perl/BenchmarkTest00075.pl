use CGI;
my $q = CGI->new;
my $value = $q->param('value');
print "Content-type: text/html\n\n";
print "<input type='text' value='$value'>";
