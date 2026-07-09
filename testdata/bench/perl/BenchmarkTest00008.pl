use Dancer2;
get '/user/:id' => sub {
    my $id = params->{id};
    my $dbh = DBI->connect("dbi:SQLite:dbname=app.db");
    my $sth = $dbh->prepare("SELECT * FROM users WHERE id = ?");
    $sth->execute($id);
    return $sth->fetchrow_hashref();
};
