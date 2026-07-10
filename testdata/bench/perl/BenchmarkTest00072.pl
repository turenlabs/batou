use Mojolicious::Lite;
get '/show' => sub {
    my $c = shift;
    my $title = $c->param('title');
    $c->render(json => { title => $title });
};
app->start;
