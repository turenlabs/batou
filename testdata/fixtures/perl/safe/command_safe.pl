#!/usr/bin/perl
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;
my $file = $cgi->param('file');

# Safe: list-form system() avoids shell interpretation
system('cat', $file);

# Safe: three-argument open for reading
open(my $fh, '<', $file) or die "Cannot open: $!";
while (<$fh>) { print; }
close($fh);

# Safe: IPC::Run with list form
# use IPC::Run qw(run);
# run ['grep', $pattern, $file], \$out;
