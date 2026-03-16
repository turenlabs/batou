# Source: CWE-89 - SQL Injection via string interpolation in Perl
# Expected: BATOU-INJ, TAINT
# OWASP: A03:2021 - Injection (SQL Injection)

use strict;
use warnings;
use DBI;

my $username = $ARGV[0];
my $dbh = DBI->connect("dbi:mysql:database=app", "root", "");
my $query = "SELECT * FROM users WHERE name = '$username'";
my $sth = $dbh->prepare($query);
$sth->execute();
