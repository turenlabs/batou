use CGI qw(:standard);
my $q = CGI->new;
my $input = $q->param('search');
my $safe = CGI::escapeHTML($input);
print header();
print "<div>Results for: $safe</div>";
