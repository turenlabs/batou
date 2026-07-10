use Mojolicious::Lite;
use File::Basename;
get '/download' => sub {
    my $c = shift;
    my $name = basename($c->param('name'));
    open(my $fh, '<', "/var/uploads/$name");
    my $data = do { local $/; <$fh> };
    close($fh);
    $c->render(data => $data);
};
app->start;
