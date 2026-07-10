use Mojolicious::Lite;
get '/version' => sub {
    my $c = shift;
    my $result = `git --version`;
    $c->render(text => $result);
};
app->start;
