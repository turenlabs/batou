use CGI;
my $cgi = CGI->new;
open(my $fh, '<', '/var/data/readme.txt');
my @content = <$fh>;
close($fh);
print "Content-type: text/plain\n\n@content";
