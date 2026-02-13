#!/usr/bin/perl
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;

# Vulnerable: two-argument open with variable
my $file = $cgi->param('file');
open(my $fh, $file);
while (<$fh>) { print; }
close($fh);
