use CGI;
my $q = CGI->new;
my $doc = $q->param('doc');
my %allowed = ('readme.txt' => 1, 'license.txt' => 1, 'changelog.txt' => 1);
die "Not allowed" unless $allowed{$doc};
open(my $fh, '<', "/var/uploads/$doc");
my @lines = <$fh>;
close($fh);
print "Content-type: text/plain\n\n@lines";
