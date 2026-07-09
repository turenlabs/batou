use Dancer2;
get '/log' => sub {
    my $logfile = params->{file};
    open(FH, "tail -100 $logfile |");
    my @lines = <FH>;
    close(FH);
    return join("\n", @lines);
};
