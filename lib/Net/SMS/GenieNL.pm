package Net::SMS::GenieNL;
#### Package information ####
# Description and copyright:
#   See POD.
####

use strict;
use Carp;
use HTTP::Request::Common qw(POST);
use HTTP::Cookies;
use LWP::UserAgent;

our $VERSION = '0.04';

my $MAX_SMS_PER_DAY = 20;
my $MAX_TEXT_LENGTH = 142;
my $SECONDS_PER_DAY = 24 * 60 * 60;

my $counter = 0;

1;

####
# Constructor new()
# Parameters:
#	Hash containing
#		USERS: Reference to array of hash references with keys 'uid', 'pwd'.
#               STATE: Optional. Reference to a tied hash for maintaining persistent state information.
#		       Tie it to Tie::Persistent or Apache::Session::File for example.
#		PROXY: Optional. HTTP proxy such as: http://localhost:8080/
#		PROXY_AUTH Optional. Array ref containing proxy username, password.
#		VERBOSE: Optional. 0 == nothing, 1 == warnings to STDERR, 2 == all messages to STDERR. Default == 1.
#		LOGFILE: Optional. If specified, then all HTTP requests and responses are appended to this file.
####
sub new {
 my $proto = shift;
 my %params = @_;
 my $class = ref($proto) || $proto;
 my $self  = {};
 bless $self,$class;

 # Check parameters
 my $param_users = $params{'USERS'};
 unless(defined($param_users)) {
  croak("USERS parameter missing!\n");
 }
 unless(@{$param_users}) {
  croak("USERS array is empty!\n");
 }
 foreach (@{$param_users}) {
  unless((ref($_) eq 'HASH') && defined($_->{'uid'}) && length($_->{'uid'}) && defined($_->{'pwd'}) && length($_->{'pwd'})) {
   croak("USERS array is invalid!\n");
  }
 }

 # Set protected fields
 $self->{'_users'} = $param_users;
 $self->{'_state'} = defined($params{'STATE'}) ? $params{'STATE'} : {};
 $self->{'_verbose'} = defined($params{'VERBOSE'}) ? $params{'VERBOSE'} : 1;
 if (defined($params{'LOGFILE'})) {
  $self->{'_logfile'} = $params{'LOGFILE'};
 }
 my $ua = new LWP::UserAgent();
 $ua->agent('Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)');
 if (defined($params{'PROXY'})) {
  $ua->proxy(['http'],$params{'PROXY'});
  if (defined($params{'PROXY_AUTH'})) {
   my $auth = $params{'PROXY_AUTH'};
   unless((ref($auth) eq 'ARRAY') && (@{$auth} == 2) && defined($auth->[0]) && defined($auth->[1])) {
    croak("PROXY_AUTH parameter, when defined, must be a reference to an array with elements username, password.\n");
   }
   $self->{'_proxy_auth'} = $auth;
  }
 }
 $self->{'_ua'} = $ua;

 # Return self reference
 return $self;
}


####
# Method:	_get_account
# Description:	Get a user account with most remaining SMS's.
# Parameters:	1. Reference to receive uid.
#		2. Reference to receive pwd.
# Returns:	Boolean.
####
sub _get_account {
 my $self = shift;
 my $uidref = shift;
 my $pwdref = shift;
 my $users = $self->{'_users'};
 my $verbose = $self->{'_verbose'};
 # Try to find first user not used within 24 hours.
 foreach my $u (@{$users}) {
  my $userstate = $self->_get_user_state($u->{'uid'});
  if ($userstate->{'lastlogin'} + $SECONDS_PER_DAY < time) {
   $$uidref = $u->{'uid'};
   $$pwdref = $u->{'pwd'};
   if ($verbose >= 2) {
    warn "Found user account not used in last 24 hours: uid=$$uidref pwd=$$pwdref\n";
   }
   return 1;
  }
 }
 # Try to find user with most remaining SMS's.
 my $remaining = 0;
 foreach my $u (@{$users}) {
  my $userstate = $self->_get_user_state($u->{'uid'});
  if ($userstate->{'remaining'} > $remaining) {
   $remaining = $userstate->{'remaining'};
   $$uidref = $u->{'uid'};
   $$pwdref = $u->{'pwd'};
  }
 }
 if ($remaining > 0) {
  if ($verbose >= 2) {
   warn "Found user account with most remaining SMS's ($remaining): uid=$$uidref pwd=$$pwdref\n";
  }
  return 1;
 }
 # No users have anything available. Try to use least recently used user.
 my $lastlogin = time;
 foreach my $u (@{$users}) {
  my $userstate = $self->_get_user_state($u->{'uid'});
  if ($userstate->{'lastlogin'} < $lastlogin) {
   $lastlogin = $userstate->{'lastlogin'};
   $$uidref = $u->{'uid'};
   $$pwdref = $u->{'pwd'};
  }
 }
 if ($verbose >= 1) {
  warn "No users have available SMS's. Using least recently used user: uid=$$uidref pwd=$$pwdref\n";
 }
 return 0;
}


####
# Method:	_get_user_state
# Description:	Gets the users state.
# Parameters:	1. uid
# Returns:	Hash reference.
####
sub _get_user_state {
 my $self = shift;
 my $uid = shift;
 my $result = $self->{'_state'};
 unless(defined($result->{'users'})) {
  $result->{'users'} = {};
 }
 $result = $result->{'users'};
 unless(defined($result->{$uid})) {
  $result->{$uid} = {};
 }
 $result = $result->{$uid};
 unless(defined($result->{'remaining'})) {
  $result->{'remaining'} = $MAX_SMS_PER_DAY;
 }
 unless(defined($result->{'lastlogin'})) {
  $result->{'lastlogin'} = 0;
 }
 if ($result->{'lastlogin'} + $SECONDS_PER_DAY < time) {
  $result->{'cookies'} = undef;
 }
 return $result;
}

####
# Method:	_login
# Description:	Logs a user in.
# Parameters:	1. uid
#		2. pwd
#		3. HTTP::Cookies
# Returns:	Boolean result
####
sub _login {
 my $self = shift;
 my $uid = shift;
 my $pwd = shift;
 my $cookies = shift;
 my $ua = $self->{'_ua'};
 my $verbose = $self->{'_verbose'};
 my $proxy_auth = $self->{'_proxy_auth'};
 my $request = POST('http://www.genie.nl:80/login/dologin',
                    'Content' => [numTries => 1,
                                  password => $pwd,
                                  username => $uid]);
 if (defined($proxy_auth)) {
  $request->proxy_authorization_basic($proxy_auth->[0], $proxy_auth->[1]);
 }
 if ($verbose >= 2) {
  warn "Trying to login.\n";
 }
 $cookies->clear();
 $ua->cookie_jar($cookies);
 $self->_log_request($request,$cookies);
 my $response = $ua->request($request);
 $self->_log_response($response);
 unless (substr($response->code,0,1) eq '3') {
  if ($verbose >= 1) {
   warn 'Login failed. Expected response code 3xx but got response code: ' . $response->code . "\n";
  }
  return 0;
 }
 # Get cookies and location from headers
 my $headers = $response->headers();
 my $location = $headers->header('Location');
 unless(defined($location) && ($location eq '/')) {
  if ($verbose >= 1) {
   warn "Login failed. Credentials perhaps incorrect.";
  }
  return 0;
 }
 @_ = $headers->header('Set-Cookie');
 unless(@_) {
  if ($verbose >= 1) {
   warn "No cookies received. Login credentials probably incorrect.\n";
  }
  return 0;
 }
 if ($verbose >= 2) {
  warn "Login OK.\n";
 }
 return 1;
}

####
# Method:	send_text
# Description:	Sends an SMS.
# Parameters:	1. Recipient phone number(s) in int'l format (comma seperated).
#		2. Body text.
# Returns:	Boolean result
####
sub send_text {
 my $self = shift;
 my $phn = shift;
 my $text = shift;
 my $uid;
 my $pwd;
 my $login = 1;
 my $verbose = $self->{'_verbose'};
 my $proxy_auth = $self->{'_proxy_auth'};
 unless($self->_get_account(\$uid,\$pwd)) {
  if ($verbose >= 1) {
   warn "No account found with available SMS's.\n";
  }
 }
 my $userstate = $self->_get_user_state($uid);
 unless(defined($userstate->{'cookies'})) {
  if ($verbose >= 2) {
   warn "User $uid has no cookies. Trying to login (to get some).\n";
  }
  $userstate->{'cookies'} = new HTTP::Cookies();
  unless($self->_login($uid,$pwd,$userstate->{'cookies'})) {
   undef($userstate->{'cookies'});
   return 0;
  }
  $userstate->{'lastlogin'} = time;
  $login = 0;
 }
 if (length($text) > $MAX_TEXT_LENGTH) {
  if ($verbose >= 1) {
   warn "Text length is too long and will be truncated to $MAX_TEXT_LENGTH characters\n";
  }
  $text = substr($text,0,$MAX_TEXT_LENGTH);
 }
 my $ua = $self->{'_ua'};
 my $request = POST('http://sendsms.genie.nl/cgi-bin/sms/send_sms.cgi',
                    'Content' => ['RECIPIENT' => $phn,
                                  'MESSAGE' => $text,
                                  'check' => 0]);
 if (defined($proxy_auth)) {
  $request->proxy_authorization_basic($proxy_auth->[0], $proxy_auth->[1]);
 }
 if ($verbose >= 2) {
  warn "Sending 'send SMS' request.\n";
 }
 $ua->cookie_jar($userstate->{'cookies'});
 $self->_log_request($request,$userstate->{'cookies'});
 my $response = $ua->request($request);
 $self->_log_response($response);
 unless(substr($response->code(),0,1) eq '2') {
  if ($verbose >= 1) {
   warn 'Send failed. Unexpected response code: ' . $response->code() . "\n";
  }
  return 0;
 }
 my $headers = $response->headers();
 # Check location
 my $location = $headers->header('Location');
 if (defined($location)) {
  # Send failed, check if we need to login again.
  if ($login) {
   # Check location
   unless($location eq 'http://www.genie.nl/alert/auth/') {
    if ($verbose >= 1) {
     warn "Send failed. Got unexpected redirect location: $location\n";
    }
    return 0;
   }
   # Try to login and send again.
   if ($verbose >= 1) {
    warn "Send failed due to invalid cookies. Trying to login and send again.\n";
   }
   unless($self->_login($uid,$pwd,$userstate->{'cookies'})) {
    undef($userstate->{'cookies'});
    return 0;
   }
   $userstate->{'lastlogin'} = time;
   $request = POST('http://sendsms.genie.nl/cgi-bin/sms/send_sms.cgi',
                   'Content' => ['RECIPIENT' => $phn,
                                 'MESSAGE' => $text,
                                 'check' => 0]);
   if (defined($proxy_auth)) {
    $request->proxy_authorization_basic($proxy_auth->[0], $proxy_auth->[1]);
   }
   if ($verbose >= 2) {
    warn "Sending 'send SMS' request again.\n";
   }
   $ua->cookie_jar($userstate->{'cookies'});
   $self->_log_request($request,$userstate->{'cookies'});
   $response = $ua->request($request);
   $self->_log_response($response);
   unless(substr($response->code(),0,1) eq '2') {
    if ($verbose >= 1) {
     warn 'Send failed. Unexpected response code: ' . $response->code() . "\n";
    }
    return 0;
   }
  }
 }
 unless($response->as_string() =~ /Je kan vandaag nog (\d+) berichten versturen./o) {
  if ($verbose >= 1) {
   warn "Send failed. Unexpected response content!\n" . $response->as_string();
  }
  return 0;
 }
 $userstate->{'remaining'} = $1;
 if (index($response->as_string(),'Het is niet mogelijk om dit bericht aan alle ontvangers te sturen omdat je dan over je daglimiet gaat.') >= 0) {
  if ($verbose >= 1) {
   warn "Send failed because there are no more remaining SMS's for this user.!\n";
  }
  return 0;
 }
 if ($verbose >= 2) {
  warn "Send OK. SMS's remaining == $1.\n";
 }
 return 1;
}

sub _log_request {
 my $self = shift;
 my $request = shift;
 my $cookies = shift;
 my $logfile = $self->{'_logfile'};
 if (defined($logfile)) {
  my $f;
  unless(open($f,">>$logfile")) {
   croak("Failed to append to log file $logfile!\n");
  }
  print $f '====== REQUEST ' . ++$counter . " ======\n" . $request->as_string() . "\n";
  if (defined($cookies)) {
   print $f "====== REQUEST $counter COOKIES ======\n" . $cookies->as_string() . "\n";
  }
  close($f);
 }
}

sub _log_response {
 my $self = shift;
 my $response = shift;
 my $logfile = $self->{'_logfile'};
 if (defined($logfile)) {
  my $f;
  unless(open($f,">>$logfile")) {
   croak("Failed to append to log file $logfile!\n");
  }
  print $f "====== RESPONSE $counter ======\n" . $response->as_string() . "\n";
  close($f);
 }
}

__END__


=head1 NAME

Net::SMS::GenieNL - Send SMS's via free SMS service of www.genie.nl.

=head1 SYNOPSIS

 use Net::SMS::GenieNL;
 use Tie::Persistent;

 my %state;

 # Read hash from file (created if not exists).
 tie %state, 'Tie::Persistent', 'GenieNL.pdb', 'rw';

 my $users = [
              {'uid' => 'j.blow','pwd' => 'secret'},
              {'uid' => 'm.jackson','pwd' => 'moonwalk'}
             ];

 my $o = new Net::SMS::GenieNL('USERS' => $users,
                               'STATE' => \%state,
                               'VERBOSE' => 2);
 $o->send_text('+31652477096','test');

 # Save hash back to file.
 untie %state;


=head1 DESCRIPTION

This package contains a class sending SMS's via the free SMS service of
www.genie.nl. It supports multiple user accounts to help overcome the max
20 SMS's per day limit. It also can maintain a persistent state hash in
which the state of the user accounts is saved so that login's aren't always
necessary etc.

=head1 CLASS METHODS

=over 4

=item new ('USERS' => $users, 'STATE' => $state, 'PROXY' => $proxy, 'PROXY_AUTH' => [$usr,$pwd], 'VERBOSE' => $level, 'LOGFILE' => $filename);

Returns a new Net::SMS::GenieNL object.

B<Parameters:>

B<USERS> Reference to an array of hash references where each hash reference
contains 2 key-value pairs where 'uid' points to the user id and 'pwd'
points to the password.

B<STATE> Optional. If specified, then it must be a hash reference. This
hash reference will be used to maintain state during the lifetime of the
Net::SMS::GenieNL object. It is advisable to used a tied hash so that the
hash can be saved to and read from a file. See L<Tie::Persistent>.

B<PROXY> Optional. If specified, then it must be a HTTP proxy URL such as
'http://www.myproxy.com:8080/'. Default is no proxy.

B<PROXY_AUTH> Optional. If specified, then it must be a reference to an
array with elements username, password for proxies that require
authentication. Default is no proxy authentication.

B<VERBOSE> Optional. If specified, it must contain an integer between 0 and
2 where 0 is no verbosity at all, 1 means print only warnings to STDERR,
and 2 means print all messages to STDERR. Default value is 1.

B<LOGFILE> Optional. If specified, it must contain the name of the file to
log all HTTP requests and responses too. Default is no logging.

=back

=head1 OBJECT METHODS

=over 4

=item send_text($recipients,$message)

Sends a SMS text message. $recipients must contain one or more recipients
specified in international format (ie +31611112222) without spaces and
seperated by commas. $message is the text message to send.

=back

=head1 HISTORY

=over 4

=item Version 0.01  2001-12-12

Initial version. It seems to work fine. Of course if www.genie.nl changes
the SMS sending process it might not work no more.

=item Version 0.02  2002-01-03

Fixed expired cookies bug. Adapted to work with some new redirection
changes in web service.

=item Version 0.03  2002-01-10

Fixed small login bug.

=item Version 0.04  2002-01-17

Added support for proxy authentication and HTTP logging.
Uses HTTP::Cookies for cookie jar instead of custom mechanism.

=back

=head1 AUTHOR

Craig Manley <cmanley@cpan.org>

=head1 COPYRIGHT

Copyright (C) 2001 Craig Manley.  All rights reserved.
This program is free software; you can redistribute it and/or modify
it under under the same terms as Perl itself. There is NO warranty;
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=cut