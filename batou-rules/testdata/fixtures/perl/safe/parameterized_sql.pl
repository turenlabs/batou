#!/usr/bin/perl
use strict;
use warnings;
use DBI;
use CGI;

my $cgi = CGI->new;
my $dbh = DBI->connect("dbi:mysql:test", "user", "pass");

# Safe: DBI placeholders with do()
my $name = $cgi->param('name');
$dbh->do("DELETE FROM users WHERE name = ?", undef, $name);

# Safe: prepare + execute with placeholders
my $sth = $dbh->prepare("SELECT * FROM users WHERE name = ? AND active = ?");
$sth->execute($name, 1);

# Safe: selectrow_array with placeholders
my @row = $dbh->selectrow_array("SELECT * FROM users WHERE id = ?", undef, $cgi->param('id'));

# Safe: quote method
my $safe_name = $dbh->quote($name);
