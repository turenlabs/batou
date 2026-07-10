use CGI;
my $cgi = CGI->new;
my $output = qx(ls /var/data);
print "Content-type: text/plain\n\n$output";
