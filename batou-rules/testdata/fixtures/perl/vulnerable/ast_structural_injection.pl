#!/usr/bin/perl
# Structural-injection fixture for the Layer-2 perlast analyzer.
# The taint source here (a hand-rolled %FORM hash parsed from QUERY_STRING) is
# NOT in the taint catalog, so the regex/taint layers alone miss these sinks.
# The AST structural tier (BATOU-PERL-AST-*) flags them anyway.
use strict;
use warnings;

my %FORM;
foreach my $pair (split /&/, $ENV{'QUERY_STRING'} // '') {
    my ($k, $v) = split /=/, $pair, 2;
    $FORM{$k} = $v;
}

# CWE-78: system() with a shell-interpolated variable.
my $host = $FORM{'host'};
system("ping -c 1 $host");

# CWE-78: backtick command execution with interpolation.
my $pat = $FORM{'pat'};
my $matches = `grep $pat /var/log/app.log`;

# CWE-22: 2-arg open lets the filename carry the mode and pipes.
my $file = $FORM{'file'};
open(LOG, "> $file");

# CWE-22: 2-arg open with a variable filename.
open(my $fh, $FORM{'name'});

# CWE-94: s///e evaluates the replacement as Perl code.
my $expr = $FORM{'expr'};
my $text = "input";
$text =~ s/(\w+)/$expr/ge;
