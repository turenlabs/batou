use CGI;
my $q = CGI->new;
my $doc = $q->param('doc');
open(my $fh, '<', "/var/uploads/" . $doc);
my @lines = <$fh>;
close($fh);
print "Content-type: text/plain\n\n@lines";
