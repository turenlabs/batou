use CGI;
my $q = CGI->new;
my $value = $q->param('value');
my $safe = CGI::escapeHTML($value);
print "Content-type: text/html\n\n";
print "<input type='text' value='$safe'>";
