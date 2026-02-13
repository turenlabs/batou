#!/usr/bin/perl
use strict;
use warnings;
use Crypt::URandom qw(urandom);
use Digest::SHA qw(sha256_hex);

# Safe: cryptographically secure random
my $token = unpack("H*", urandom(32));

# Safe: SHA-256 instead of MD5/SHA1
my $hash = sha256_hex($data);

# Safe: proper file permissions
chmod(0600, $secret_file);
mkdir($private_dir, 0700);
