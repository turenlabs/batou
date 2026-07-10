use CGI;
my $q = CGI->new;
print "Content-type: text/html\n\n";
print "<div class='profile'>" . $q->param('bio') . "</div>";
