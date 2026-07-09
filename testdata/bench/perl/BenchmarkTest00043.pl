use Mojolicious::Lite;
get '/download' => sub {
    my $c = shift;
    my $name = $c->param('name');
    open(my $fh, '<', $name);
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(data => $data);
};
app->start;
