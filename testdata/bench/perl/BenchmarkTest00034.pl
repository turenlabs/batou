use Dancer2;
get '/log' => sub {
    my $logfile = params->{file};
    open(my $fh, '<', "/var/log/$logfile");
    my @lines = <$fh>;
    close($fh);
    return join("\n", @lines);
};
