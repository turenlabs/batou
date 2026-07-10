use Dancer2;
post '/save' => sub {
    my $filename = params->{filename};
    my $content = params->{content};
    open(my $fh, '>', $filename);
    print $fh $content;
    close($fh);
    return { saved => 1 };
};
