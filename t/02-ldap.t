use strict;
use warnings;

use Test::More import => ['!pass'];
use Mock::Quick;

my $auth_as = '';

my $noerr = qclass(
    -with_new => 1,
    is_error => 0,
    );
    
my $err = qclass(
    -with_new => 1,
    is_error => 1,
    error => 'bogus mock',
    );
    
my $emptyentries = qclass(
    -with_new => 0,
    is_error => 0,
    entries => 0,
    );
    
my $entries1 = qclass(
    -with_new => 1,
    is_error => 0,
    entries => 1,
    );

my $entry1 = qclass(
    -with_new => 1,
    vals => {cn => "David Precious", dn => 'dprecious', name => 'David Precious', userPrincipalName => 'dprecious@foo.com', sAMAcountName=>'dprecious'},
#    vals => {dn => 'dprecious', name => 'David Precious', userPrincipalName => 'dprecious@foo.com', cn => 'dprecious'},
    get_value => sub { 
        my $self = shift;
        my $arg = shift;
        return $self->vals()->{$arg};
        },
    );
    
my $detail = qclass(
    -with_new => 1,
    is_error => 0,
    entries => 1,
    entry => sub { return $entry1->package->new; },
    );

my $mod = qclass(
    -implement => 'Net::LDAP',
    -with_new => 0,
    new => sub { my $cls = shift; 
    bless {}, $cls; },
    disconnect => sub { },
    unbind => sub { $auth_as = ''; },
    bind => sub { if ($_[1] =~ /^cn=dprecious,/) { return $noerr->package->new; } else { return $err->package->new; } },
    search => sub {
        my $self = shift;
        my %args = @_;
#        if (my ($uname) = $args{filter} =~ /^\(&\(objectClass=user\)\(cn=([^,]+)\)$/) {
		 if (my ($uname) = $args{filter} =~ /^\(&\(objectClass=user\)\(cn=([^,]+)\)$/) {
			print "uname = $uname\n";
            return $detail->package->new;
        } elsif (my ($name, $role) = $args{filter} =~ /^\(\&\(memberOf=cn=(.+)\)\("cn="(.+)\)/) {
#		} elsif (my ($name, $role) = $args{filter} =~ /^\(\&\(objectClass=user\)\(sAMAccountName=(.+)\)\(memberof=cn=([^,]+)/) {
        if ($name eq "dprecious") {
                
                diag("ROLE: " . $role);
                if ($role eq "Jever" or $role eq "Budvar") {
                    return $entries1->package->new;
                } else {
                    return $emptyentries->package->new;
                }
            }
            return $emptyentries->package->new;
        } else {
            return $err->package->new;
        }
    },
);

use t::ldap::LDAPTestApp;

use Dancer ':syntax';

my $dancer_version;
BEGIN {
    $dancer_version = (exists &dancer_version) ? int(dancer_version()) : 1;
    require Dancer::Test;
    if ($dancer_version == 1) {
        Dancer::Test->import();
    } else {
        Dancer::Test->import('t::ldap::LDAPTestApp');
    }
}


# First, without being logged in, check we can access the index page, but not
# stuff we need to be logged in for:

response_content_is   [ GET => '/' ], 'Index always accessible',
    'Index accessible while not logged in';

response_redirect_location_is  [ GET => '/loggedin' ], 
    'http://localhost/login?return_url=%2Floggedin',
    '/loggedin redirected to login page when not logged in';

response_redirect_location_is  [ GET => '/beer' ],
    'http://localhost/login?return_url=%2Fbeer',
    '/beer redirected to login page when not logged in';

response_redirect_location_is  [ GET => '/regex/a' ], 
    'http://localhost/login?return_url=%2Fregex%2Fa',
    '/regex/a redirected to login page when not logged in';

# OK, now check we can't log in with fake details

response_status_is  [ 
    POST => '/login', { body => { username => 'foo', password => 'bar' } }
], 401, 'Login with fake details fails';

# ... and that we can log in with real details
response_status_is [
    POST => '/login', { body => { username => 'dprecious', password => 'blafasel' } }
], 302, 'Login with real details succeeds';


# Now we're logged in, check we can access stuff we should...

response_status_is [ GET => '/loggedin' ], 200,
    'Can access /loggedin now we are logged in';


response_content_is [ GET => '/loggedin' ], 'You are logged in',
    'Correct page content while logged in, too';;

response_content_is [ GET => '/name' ], 'Hello, David Precious',
    'Logged in user details via logged_in_user work';


response_content_is [ GET => '/roles' ], 'Budvar,Jever',
    'Correct roles for logged in user';


# Check we can request something which requires a role we have....
response_status_is [ GET => '/beer' ], 200,
    'We can request a route (/beer) requiring a role we have...';

# Check we can request a route that requires any of a list of roles, one of
# which we have:
response_status_is [ GET => '/anyrole' ], 200,
    "We can request a multi-role route requiring with any one role";

response_status_is [ GET => '/allroles' ], 200,
    "We can request a multi-role route with all roles required";


# And also a route declared as a regex (this should be no different, but
# melmothX was seeing issues with routes not requiring login when they should...
response_status_is [ GET => '/regex/a' ], 200,
    "We can request a regex route when logged in";

# ... but can't request something requiring a role we don't have
response_redirect_location_is  [ GET => '/piss' ],
    'http://localhost/login/denied?return_url=%2Fpiss',
    "We cannot request a route requiring a role we don't have";

# Check the realm we authenticated against is what we expect
response_content_is [ GET => '/realm' ], 'ldap',
    'Authenticated against expected realm';

# Now, log out
response_status_is [
    POST => '/logout', {},
], 200, 'Logging out returns 200';


# Check we can't access protected pages now we logged out:
response_redirect_location_is  [ GET => '/loggedin' ],
    'http://localhost/login?return_url=%2Floggedin',
    '/loggedin redirected to login page after logging out';

response_redirect_location_is  [ GET => '/beer' ], 
    'http://localhost/login?return_url=%2Fbeer',
    '/beer redirected to login page after logging out';

# Now, log out again
response_status_is [
    POST => '/logout', {},
], 200, 'Logged out again';

foreach my $entry (@{ read_logs() }) {
  diag("LOG: " . $entry->{level} . ": " . $entry->{message} . "\n");
}


done_testing();


