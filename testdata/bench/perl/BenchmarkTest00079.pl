use CGI;
my $cgi = CGI->new;
my $content = $cgi->param('msg');
print "Content-type: text/html\n\n";
print "<div class='error'>$content</div>";
