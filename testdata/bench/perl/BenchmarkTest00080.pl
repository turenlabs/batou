use Dancer2;
use HTML::Entities;
get '/error' => sub {
    my $msg = params->{msg};
    my $safe = encode_entities($msg);
    return "<div class='error'>$safe</div>";
};
