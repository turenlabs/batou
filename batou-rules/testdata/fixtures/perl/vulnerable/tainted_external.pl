#!/usr/bin/perl
# External-origin fixture for the reworked perlast analyzer.
#
# Every dangerous shape below is fed by a DISTINCT recognised external source
# (CGI param, Plack request, @ARGV, %ENV, <STDIN>). The external-origin gate
# must let these through — this proves the gate distinguishes user-controlled
# operands from the safe local/constant operands it now suppresses, rather than
# being a blanket "disable everything" switch.
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;

# CWE-78: system() shell form, operand from a CGI request parameter.
my $host = $cgi->param('host');
system("ping -c 1 $host");

# CWE-78: backticks, operand from a Plack request parameter.
my $pat = $req->param('pat');
my $hits = `grep $pat /var/log/app.log`;

# CWE-78: qx, operand from an environment variable.
my $tag = $ENV{'BUILD_TAG'};
my $info = qx/git show $tag/;

# CWE-78: 2-arg piped open, command from a CLI argument.
my $cmd = $ARGV[0];
open(my $p, "$cmd |");

# CWE-22: 2-arg open whose filename carries the mode, path from STDIN.
my $line = <STDIN>;
chomp $line;
open(my $fh, "> $line");

# CWE-94: s///e whose bare-scalar replacement is user-controlled code.
my $expr = $cgi->param('expr');
my $text = "x";
$text =~ s/(\w+)/$expr/ge;
