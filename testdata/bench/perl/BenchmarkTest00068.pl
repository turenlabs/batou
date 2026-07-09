use Dancer2;
use HTML::Entities;
get '/profile' => sub {
    my $bio = params->{bio};
    my $safe = encode_entities($bio);
    return "<div class='profile'>$safe</div>";
};
