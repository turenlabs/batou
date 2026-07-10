use CGI;
use JSON;
my $cgi = CGI->new;
my $comment = $cgi->param('comment');
print "Content-type: application/json\n\n";
print encode_json({ comment => $comment });
