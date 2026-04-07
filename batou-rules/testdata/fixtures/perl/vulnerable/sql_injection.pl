#!/usr/bin/perl
use strict;
use warnings;
use DBI;
use CGI;

my $cgi = CGI->new;
my $dbh = DBI->connect("dbi:mysql:test", "user", "pass");

# Vulnerable: string interpolation in do()
my $name = $cgi->param('name');
$dbh->do("DELETE FROM users WHERE name = '$name'");

# Vulnerable: string concatenation in do()
my $id = $cgi->param('id');
$dbh->do("SELECT * FROM users WHERE id = " . $id);

# Vulnerable: interpolation in prepare()
my $table = $cgi->param('table');
my $sth = $dbh->prepare("SELECT * FROM $table WHERE active = 1");

# Vulnerable: interpolation in selectrow_array
my $user = $cgi->param('user');
my @row = $dbh->selectrow_array("SELECT * FROM users WHERE name = '$user'");
