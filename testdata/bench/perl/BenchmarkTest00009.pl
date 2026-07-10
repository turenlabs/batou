use Mojolicious::Lite;
post '/login' => sub {
    my $c = shift;
    my $user = $c->param('username');
    my $pass = $c->param('password');
    my $dbh = DBI->connect("dbi:mysql:auth", "root", "");
    $dbh->do("SELECT * FROM accounts WHERE user='$user' AND pass='$pass'");
};
app->start;
