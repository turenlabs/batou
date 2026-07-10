use Dancer2;
get '/config' => sub {
    open(my $fh, '<', '/app/config/settings.yml');
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
};
