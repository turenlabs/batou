use Mojolicious::Lite;
get '/greet' => sub {
    my $c = shift;
    my $user = $c->param('user');
    $c->render(text => "<h1>Welcome " . xml_escape($user) . "</h1>", format => 'html');
};
app->start;
