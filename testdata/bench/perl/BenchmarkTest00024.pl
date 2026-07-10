use Mojolicious::Lite;
use IPC::Run qw(run);
get '/lookup' => sub {
    my $c = shift;
    my $domain = $c->param('domain');
    run(["nslookup", $domain], \my $out, \my $err);
    $c->render(text => $out);
};
app->start;
