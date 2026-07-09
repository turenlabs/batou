use Mojolicious::Lite;
get '/search' => sub {
    my $c = shift;
    my $query = $c->param('q');
    my $dbh = DBI->connect("dbi:Pg:dbname=app", "", "");
    my $sth = $dbh->prepare("SELECT * FROM items WHERE title LIKE ?");
    $sth->execute("%$query%");
};
app->start;
