#!/usr/bin/perl
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;

# Vulnerable: eval with variable
my $expr = $cgi->param('expr');
my $result = eval($expr);

# Vulnerable: eval with string
eval $expr;

# Vulnerable: eval with double-quoted string interpolation
my $field = $cgi->param('field');
eval "print $field";
