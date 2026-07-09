use Dancer2;
get '/products' => sub {
    my $category = params->{cat};
    my $dbh = DBI->connect("dbi:mysql:shop");
    my $sth = $dbh->prepare("DELETE FROM products WHERE category = ?");
    $sth->execute($category);
    return { status => 'deleted' };
};
