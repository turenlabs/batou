use Mojolicious::Lite;
get '/view' => sub {
    my $c = shift;
    open(my $fh, '<', '/var/www/index.html');
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(text => $data);
};
app->start;
