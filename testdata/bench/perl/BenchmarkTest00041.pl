use CGI;
my $cgi = CGI->new;
my $file = $cgi->param('file');
open(FH, $file);
my @content = <FH>;
close(FH);
print "Content-type: text/plain\n\n@content";
