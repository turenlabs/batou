use CGI;
my $q = CGI->new;
open(my $fh, '<', '/reports/monthly_summary.csv');
my $data = do { local $/; <$fh> };
close($fh);
print "Content-type: text/html\n\n$data";
