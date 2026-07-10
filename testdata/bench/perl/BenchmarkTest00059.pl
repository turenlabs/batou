use Dancer2;
get '/config' => sub {
    my $file = params->{file};
    open(my $fh, '<', $file);
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
};
