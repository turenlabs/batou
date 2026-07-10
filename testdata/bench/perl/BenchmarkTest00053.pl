use Dancer2;
get '/template' => sub {
    my $tpl = params->{template};
    open(my $fh, '<', "/app/templates/" . $tpl);
    my $html = do { local $/; <$fh> };
    close($fh);
    return $html;
};
