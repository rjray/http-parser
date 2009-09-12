# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

use strict;
use Test::More tests => 11;

# <1>
BEGIN { use_ok('HTTP::Parser') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $parser = HTTP::Parser->new();
my @lines = ('GET / HTTP/1.1','Host: localhost','Connection: close','');
my @ok = (-2,-2,-2,0);

# <4>
my $result;
for my $line(@lines) {
  $result = $parser->add("$line\x0d\x0a");
  is($result,shift @ok,"Passing '$line'");
}

# <6>
if($result) {
  skip "Didn't get request object", 6;
} else {
  my $req = $parser->request();
  isa_ok($req,'HTTP::Request');

  is($req->method(),'GET','Method');

  my $uri = $req->uri();
  isa_ok($uri,'URI');
  is($uri->path(),'/','URI path');

  my @head;
  $req->headers->scan(sub { push @head, [@_] }); 
  ok(eq_set(\@head,[[Connection => 'close'], [Host => 'localhost'],
   ['X-HTTP-Version' => '1.1']]),'Headers');
  is($req->content,'','Content');
}

