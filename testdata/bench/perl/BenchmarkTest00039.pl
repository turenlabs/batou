use Dancer2;
post '/deploy' => sub {
    my $branch = params->{branch};
    system("git checkout $branch && make deploy");
    return { deployed => 1 };
};
