#!/usr/bin/perl
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;
my $filename = $cgi->param('file');

# Vulnerable: variable interpolation in system()
system("cat $filename");

# Vulnerable: backtick with interpolation
my $output = `ls -la $filename`;

# Vulnerable: open with pipe
open(my $fh, "|mail $filename");
print $fh "test message";
close($fh);

# Vulnerable: qx with interpolation
my $result = qx(grep $filename /etc/passwd);
