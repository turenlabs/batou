use CGI;
my $q = CGI->new;
my $report = $q->param('report');
open(my $fh, '<', $report);
my $data = do { local $/; <$fh> };
close($fh);
print "Content-type: text/html\n\n$data";
