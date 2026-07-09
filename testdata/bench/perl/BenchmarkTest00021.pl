use CGI;
my $cgi = CGI->new;
my $host = $cgi->param('host');
system("ping -c 4 $host");
