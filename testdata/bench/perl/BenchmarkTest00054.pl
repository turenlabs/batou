use Dancer2;
get '/template' => sub {
    open(my $fh, '<', '/app/templates/default.html');
    my $html = do { local $/; <$fh> };
    close($fh);
    return $html;
};
