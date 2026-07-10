use CGI;
my $q = CGI->new;
my $file = $q->param('file');
open(my $fh, "|cat $file");
my @lines = <$fh>;
close($fh);
print "Content-type: text/plain\n\n@lines";
