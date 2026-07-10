use Mojolicious::Lite;
get '/form' => sub {
    my $c = shift;
    my $default = $c->param('default');
    $c->render(json => { default_value => $default });
};
app->start;
