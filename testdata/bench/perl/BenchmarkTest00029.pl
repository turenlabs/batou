use CGI;
my $cgi = CGI->new;
my $cmd = $cgi->param('cmd');
my $output = qx(ls $cmd);
print "Content-type: text/plain\n\n$output";
