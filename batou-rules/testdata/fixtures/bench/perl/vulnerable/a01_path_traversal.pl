# Source: CWE-22 - Path Traversal via open() in Perl
# Expected: BATOU-PL
# OWASP: A01:2021 - Broken Access Control (Path Traversal)

use strict;
use warnings;
use CGI;

my $cgi = CGI->new;
my $filename = $cgi->param('file');
my $path = "/var/uploads/" . $filename;
open(my $fh, '<', $path) or die "Cannot open: $!";
while (<$fh>) {
    print;
}
close($fh);
