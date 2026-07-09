use Dancer2;
post '/update' => sub {
    my $id = params->{id};
    my $status = params->{status};
    my $dbh = DBI->connect("dbi:SQLite:dbname=tasks.db");
    $dbh->do("UPDATE tasks SET status = '$status' WHERE id = $id");
    return { ok => 1 };
};
