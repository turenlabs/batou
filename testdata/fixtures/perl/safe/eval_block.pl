#!/usr/bin/perl
use strict;
use warnings;

# Safe: eval block for exception handling (not string eval)
eval {
    my $result = some_risky_function();
    process($result);
};
if ($@) {
    warn "Error occurred: $@";
}

# Safe: eval block with try-catch pattern
eval {
    open(my $fh, '<', '/etc/config.conf') or die "Cannot open: $!";
    my $config = do { local $/; <$fh> };
    close($fh);
};
