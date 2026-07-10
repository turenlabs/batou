use Dancer2;
post '/update' => sub {
    my $id = params->{id};
    my $status = params->{status};
    my $dbh = DBI->connect("dbi:SQLite:dbname=tasks.db");
    my $sth = $dbh->prepare("UPDATE tasks SET status = ? WHERE id = ?");
    $sth->execute($status, $id);
    return { ok => 1 };
};
