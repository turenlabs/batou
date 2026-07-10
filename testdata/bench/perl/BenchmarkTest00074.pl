use Dancer2;
use HTML::Entities;
get '/search' => sub {
    my $query = params->{q};
    my $safe = encode_entities($query);
    return "<html><body>Search: $safe</body></html>";
};
