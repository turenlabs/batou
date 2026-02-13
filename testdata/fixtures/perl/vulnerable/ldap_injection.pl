#!/usr/bin/perl
use strict;
use warnings;
use Net::LDAP;
use CGI;

my $cgi = CGI->new;
my $ldap = Net::LDAP->new('ldap.example.com');

# Vulnerable: LDAP filter with interpolation
my $user = $cgi->param('username');
my $result = $ldap->search(filter => "(uid=$user)");

# Vulnerable: LDAP filter from variable
my $filter = "(cn=" . $cgi->param('name') . ")";
my $result2 = $ldap->search(filter => $filter);
