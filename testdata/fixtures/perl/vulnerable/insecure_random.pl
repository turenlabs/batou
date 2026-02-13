#!/usr/bin/perl
use strict;
use warnings;

# Vulnerable: srand with time (predictable seed)
srand(time);
my $token = int(rand(1000000));

# Vulnerable: fixed srand seed
srand(42);
my $secret = rand(100);

# Vulnerable: rand for session token
my $session_id = "sess_" . int(rand(999999));
