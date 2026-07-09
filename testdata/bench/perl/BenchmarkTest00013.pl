use Dancer2;
get '/products' => sub {
    my $category = params->{cat};
    my $dbh = DBI->connect("dbi:mysql:shop");
    $dbh->do("DELETE FROM products WHERE category = '$category'");
    return { status => 'deleted' };
};
