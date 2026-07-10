use Mojolicious::Lite;
get '/search' => sub {
    my $c = shift;
    my $query = $c->param('q');
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    $dbh->do("SELECT * FROM items WHERE title LIKE '%$query%'");
};
app->start;
