#!/usr/bin/perl
use strict;
use warnings;

# Vulnerable: world-writable file
chmod(0777, $file);

# Vulnerable: world-writable directory
mkdir($dir, 0777);

# Vulnerable: world-readable/writable
chmod(0666, $logfile);
