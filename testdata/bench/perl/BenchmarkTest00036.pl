use CGI;
my $q = CGI->new;
my $action = $q->param('action');
my %allowed = (status => 1, restart => 1, stop => 1);
if ($allowed{$action}) {
    system("systemctl", $action, "myservice");
}
print "Content-type: text/html\n\nDone";
