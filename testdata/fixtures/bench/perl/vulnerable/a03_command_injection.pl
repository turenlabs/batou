# Source: CWE-78 - OS Command Injection via system() in Perl
# Expected: BATOU-PL
# OWASP: A03:2021 - Injection (Command Injection)

use strict;
use warnings;

my $input = $ARGV[0];
my $cmd = "ping -c 1 " . $input;
system($cmd);
