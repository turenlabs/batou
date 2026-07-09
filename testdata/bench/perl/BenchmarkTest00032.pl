use Mojolicious::Lite;
post '/archive' => sub {
    my $c = shift;
    my $dir = $c->param('directory');
    system("tar", "czf", "archive.tar.gz", $dir);
    $c->render(text => 'Done');
};
app->start;
