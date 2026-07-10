use Mojolicious::Lite;
post '/login' => sub {
    my $c = shift;
    my $user = $c->param('username');
    my $pass = $c->param('password');
    my $dbh = DBI->connect("dbi:mysql:auth", "root", "");
    my $sth = $dbh->prepare("SELECT * FROM accounts WHERE user = ? AND pass = ?");
    $sth->execute($user, $pass);
};
app->start;
