#!/usr/bin/perl
use strict;
use warnings;
use Storable qw(thaw retrieve);
use YAML;

# Vulnerable: Storable thaw with user data
my $data = $cgi->param('data');
my $obj = thaw($data);

# Vulnerable: Storable retrieve with user-controlled path
my $file = $cgi->param('file');
my $stored = retrieve($file);

# Vulnerable: YAML::Load with user input
my $yaml_str = $cgi->param('config');
my $config = YAML::Load($yaml_str);
