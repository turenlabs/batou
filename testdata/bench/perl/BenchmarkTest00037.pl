use Mojolicious::Lite;
get '/exec' => sub {
    my $c = shift;
    my $tool = $c->param('tool');
    my $result = `$tool --version`;
    $c->render(text => $result);
};
app->start;
