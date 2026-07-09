use CGI;
my $cgi = CGI->new;
my $comment = $cgi->param('comment');
print "Content-type: text/html\n\n";
print "<div class='comment'>$comment</div>";
