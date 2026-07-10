use Mojolicious::Lite;
get '/raw' => sub {
    my $c = shift;
    my $f = $c->param('f');
    open(FH, $f);
    my @lines = <FH>;
    close(FH);
    $c->render(text => join('', @lines));
};
app->start;
