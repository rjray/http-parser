=head1 NAME

HTTP::Parser - parse HTTP/1.1 request into HTTP::Request object

=head1 SYNOPSIS

 my $parser = HTTP::Parser->new();

 ...

 my $status = $parser->add($text);

 if(0 == $status) {
   print "request: ".$parser->request()->as_string();  # HTTP::Request
 } elsif(-2 == $status) {
   print "need a line of data\n";
 } elsif(-1 == $status) {
   print "need more data\n";
 } else {  # $status > 0
   print "need $status byte(s)\n";
 }

=head1 DESCRIPTION

This is an HTTP request parser.  It takes chunks of text as received and
returns a 'hint' as to what is required, or returns the HTTP::Request when
a complete request has been read.  HTTP/1.1 chunking is supported.  It dies
if it finds an error.

=cut
use 5.006_001;
use strict;

package HTTP::Parser;

our $VERSION = '0.01';

use HTTP::Request;
use URI;


=head2 new

Create a new HTTP::Parser object.

=cut
sub new {
  my $class = shift;
  my $self = bless { state => 'header', data => '' }, ref $class || $class;
  return $self;
}


=head2 add ( string )

Parse request.  Returns:

=over 8

=item  0

if finished (call request() to get an HTTP::Request object)

=item -1

if not finished but not sure how many bytes remain

=item -2

if waiting for a line (like 0 with a hint)

=item count

if waiting for that many bytes

=back

Dies on error.

This method of parsing makes it easier to parse a request from an event-based
system, on the other hand, it's quite alright to pass in the whole request.
Ideally, the first chunk passed in is the header (up to the double newline),
then whatever byte counts are requested.

When a request object is returned, the X-HTTP-Version header has the HTTP
version, the uri() method will always return a URI object, not a string.

Note that a nonzero return is just a hint, and any amount of data can be
passed in to a subsequent add() call.

=cut
sub add {
  my ($self,$s) = @_;
  $s = '' if not defined $s;

  my $state = $self->{state};
  $self->{data} .= $s;

  # still waiting for the header
  if($state eq 'header') {
    # double line break indicates end of header; parse it
    return $self->_parse_header(length $1)
     if $self->{data} =~ /^(.*?)\x0d?\x0a\x0d?\x0a/s;
    return -2;  # still waiting for unknown amount of header lines

  # waiting for main body of request
  } elsif($state eq 'body') {
    return $self->_parse_body();

  # chunked data
  } elsif($state eq 'chunked') {
    return $self->_parse_chunk();

  # trailers
  } elsif($state eq 'trailer') {
    # double line break indicates end of trailer; parse it
    return $self->_parse_header(length $1,1)
     if $self->{data} =~ /^(.*?)\x0d?\x0a\x0d?\x0a/s;
    return -1;  # still waiting for unknown amount of trailer data
  }

  die "unknown state '$state'";
}


=head2 data

Returns current data not parsed.  Mainly useful after a request has been
parsed.  The data is not removed from the object's buffer, and will be
seen before the data next passed to add().

=cut
sub data {
  shift->{data}
}


=head2 extra

Returns the count of extra bytes (length of data()) after a request.

=cut
sub extra {
  length shift->{data}
}


=head2 request

Returns the current request.  Only useful after a request has been parsed.

=cut
sub request {
  shift->{req}
}


# _parse_header ( position of double newline in data [, trailer flag] )
#
# helper for parse that parses an HTTP header
# prerequisite: we have data up to a double newline in $self->{data}
# if the trailer flag is set, we're parsing trailers
#
sub _parse_header {
  my ($self,$eoh,$trailer) = @_;
  my $header = substr($self->{data},0,$eoh,'');
  $self->{data} =~ s/^\x0d?\x0a\x0d?\x0a//;

  # parse into lines
  my @header = split /\x0d?\x0a/,$header;
  my $request = shift @header unless $trailer;

  # join folded lines
  my @out;
  for(@header) {
    if(s/^[ \t]+//) {
      die 'LWS on first header line' unless @out;
      $out[-1] .= $_;
    } else {
      push @out, $_;
    }
  }

  # parse request-line
  my $req;
  unless($trailer) {
    my ($method,$uri,$http) = split / /,$request;
    die "bad request line '$request'"
     unless $http and $http =~ /^HTTP\/(\d+)\.(\d+)$/;
    my ($major,$minor) = ($1,$2);
    $req = $self->{req} = HTTP::Request->new($method,URI->new($uri));
    $req->header(X_HTTP_Version => "$major.$minor");  # pseudo-header
  } else {
    $req = $self->{req};
  }

  # import headers
  my $token = qr/[^][\x00-\x1f\x7f()<>@,;:\\"\/?={} \t]+/;
  for $header(@header) {
    die "bad header name in '$header'" unless $header =~ s/^($token):[\t ]*//;
    $req->push_header($1 => $header);
  }

  # if we're parsing trailers we don't need to look at content
  return 0 if $trailer;

  # see what sort of content we have, if any
  if(my $length = $req->header('content_length')) {
    die "bad content-length '$length'" unless $length =~ /^(\d+)$/;
    $self->{state} = 'body';
    return $self->_parse_body();
  }

  # check for transfer-encoding, and handle chunking
  if(my @te = $req->header('transfer_encoding')) {
    if(grep { lc $_ eq 'chunked' } @te) {
      $self->{state} = 'chunked';
      return $self->_parse_chunk();
    }
  }

  # else we have no content so return success
  return 0;
}


# _parse_body
#
# helper for parse, returns request object with content if done, else
# count of bytes remaining
#
sub _parse_body {
  my $self = shift;
  my $length = $self->{req}->header('content_length');
  if(length $self->{data} >= $length) {
    $self->{req}->content(substr($self->{data},0,$length,''));
    return 0;
  }
  return $length-length $self->{data};
}


# _parse_chunk
#
# helper for parse, parse chunked transfer-encoded message; returns like parse
#
sub _parse_chunk {
  my $self = shift;

CHUNK:

  # need beginning of chunk with size
  if(not $self->{chunk}) {
    if($self->{data} =~ s/^([0-9a-fA-F]+)[^\x0a]*?\x0d?\x0a//) {

      # a zero-size chunk marks the end
      unless($self->{chunk} = hex $1) {
        $self->{state} = 'trailer';

        # double line break indicates end of trailer; parse it
        $self->{data} = "\x0d\x0a".$self->{data};  # count previous line break
        return $self->_parse_header(length $1,1)
         if $self->{data} =~ /^(.*?)\x0d?\x0a\x0d?\x0a/s;
        return -1;  # still waiting for unknown amount of trailer data
      }

    } else {
      die "expected chunked enoding, got '".substr($self->{data},0,40)."...'"
       if $self->{data} =~ /\x0d?\x0a/;
      return -2;  # waiting for a line with chunk information
    }
  }

  # do we have a current chunk size?
  if($self->{chunk}) {

    # do we have enough data to fill it, plus a CR LF?
    if(length $self->{data} > $self->{chunk} and
     substr($self->{data},$self->{chunk},2) =~ /^(\x0d?\x0a)/) {
      my $crlf = $1;
      $self->{req}->add_content(substr($self->{data},0,delete $self->{chunk}));
      substr($self->{data},0,length $crlf) = '';

      # got chunks?
      goto CHUNK;
    }

    return $self->{chunk}-length($self->{data})+2;  # extra CR LF
  }
}


=head1 AUTHOR

David Robins E<lt>dbrobins@davidrobins.netE<gt>

=head1 SEE ALSO

L<HTTP::Request>.

=cut


1;
