use CGI;
use File::Basename;
my $cgi = CGI->new;
my $logfile = basename($cgi->param('logfile'));
open(my $fh, '>>', "/var/log/app/$logfile");
print $fh "entry logged\n";
close($fh);
print "Content-type: text/html\n\nLogged";
