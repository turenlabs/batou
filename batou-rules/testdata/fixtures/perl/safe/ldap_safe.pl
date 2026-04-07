#!/usr/bin/perl
use strict;
use warnings;
use Net::LDAP;
use Net::LDAP::Util qw(escape_filter_value escape_dn_value);

# Safe: LDAP filter values escaped with Net::LDAP::Util
sub search_user_safe {
    my ($ldap, $username) = @_;

    # Escape user input before using in LDAP filter
    my $safe_username = escape_filter_value($username);

    my $result = $ldap->search(
        base   => "dc=example,dc=com",
        filter => "(uid=$safe_username)",
    );

    return $result->entries;
}

# Safe: DN values escaped
sub lookup_dn_safe {
    my ($ldap, $user_input) = @_;

    my $safe_dn = escape_dn_value($user_input);

    my $result = $ldap->search(
        base   => "ou=$safe_dn,dc=example,dc=com",
        filter => "(objectClass=person)",
    );

    return $result->entries;
}
