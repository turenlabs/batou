use Mojolicious::Lite;
get '/view' => sub {
    my $c = shift;
    my $path = $c->param('path');
    open(my $fh, '<', $path);
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(text => $data);
};
app->start;
