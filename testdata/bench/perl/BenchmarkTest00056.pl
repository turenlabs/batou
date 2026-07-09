use Mojolicious::Lite;
get '/raw' => sub {
    my $c = shift;
    my $f = $c->param('f');
    return $c->render(text => 'Invalid', status => 400)
        if $f =~ /\.\./;
    open(my $fh, '<', "/var/data/$f");
    my @lines = <$fh>;
    close($fh);
    $c->render(text => join('', @lines));
};
app->start;
