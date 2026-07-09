use Mojolicious::Lite;
get '/lookup' => sub {
    my $c = shift;
    my $domain = $c->param('domain');
    my $result = `nslookup $domain`;
    $c->render(text => $result);
};
app->start;
