use CGI qw(:standard);
my $q = CGI->new;
my $input = $q->param('search');
print header();
print "<div>Results for: $input</div>";
