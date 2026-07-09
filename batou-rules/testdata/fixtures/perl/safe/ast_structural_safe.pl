#!/usr/bin/perl
# Safe counterpart: the perlast Layer-2 analyzer must NOT flag these.
use strict;
use warnings;

my $path = $ARGV[0];

# Safe: 3-arg open with an explicit literal mode.
open(my $fh, "<", $path) or die "cannot open: $!";

# Safe: list form of system() bypasses the shell entirely.
system("ping", "-c", "1", $path);

# Safe: fully literal command, no interpolation.
my $when = `date`;

# Safe: substitution WITHOUT the /e modifier — plain text replacement.
my $t = "abc";
$t =~ s/(\w+)/[$1]/g;
