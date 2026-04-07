#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use HTML::Entities;

my $cgi = CGI->new;

# Safe: encode_entities before output
my $name = $cgi->param('name');
print "Content-Type: text/html\n\n";
print "<h1>Hello " . encode_entities($name) . "</h1>";

# Safe: CGI escapeHTML
print "<p>" . $cgi->escapeHTML($cgi->param('query')) . "</p>";
