use CGI;
my $cgi = CGI->new;
my $logfile = $cgi->param('logfile');
open(my $fh, '>>', $logfile);
print $fh "entry logged\n";
close($fh);
print "Content-type: text/html\n\nLogged";
