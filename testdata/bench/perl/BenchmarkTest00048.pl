use Dancer2;
get '/readme' => sub {
    open(my $fh, '<', '/app/README.md');
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
};
