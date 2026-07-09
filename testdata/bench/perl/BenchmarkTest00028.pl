use Dancer2;
post '/convert' => sub {
    my $input = params->{filename};
    exec("convert", $input, "output.png");
};
