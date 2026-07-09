use Mojolicious::Lite;
get '/order' => sub {
    my $c = shift;
    my $order_id = $c->param('oid');
    my $dbh = DBI->connect("dbi:Pg:dbname=store");
    my $row = $dbh->selectrow_hashref("SELECT * FROM orders WHERE oid = ?", undef, $order_id);
    $c->render(json => $row);
};
app->start;
