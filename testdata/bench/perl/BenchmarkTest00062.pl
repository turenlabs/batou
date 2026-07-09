use CGI;
use HTML::Entities;
my $cgi = CGI->new;
my $name = $cgi->param('name');
my $safe = encode_entities($name);
print "Content-type: text/html\n\n";
print "<h1>Hello $safe</h1>";
