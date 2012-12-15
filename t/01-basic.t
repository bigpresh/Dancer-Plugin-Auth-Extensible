use strict;
use warnings;

use Test::More import => ['!pass'];
use t::lib::TestApp;
use Dancer ':syntax';

my $dancer_version;
BEGIN {
    $dancer_version = (exists &dancer_version) ? int(dancer_version()) : 1;
    require Dancer::Test;
    if ($dancer_version == 1) {
        Dancer::Test->import();
    } else {
        Dancer::Test->import('t::lib::TestApp');
    }
}

# First, without being logged in, check we can access the index page, but not
# stuff we need to be logged in for:

response_content_is   [ GET => '/' ], 'Index always accessible',
    'Index accessible while not logged in';

response_redirect_location_is  [ GET => '/loggedin' ], 'http://localhost/login',
    '/loggedin redirected to login page when not logged in';

response_redirect_location_is  [ GET => '/beer' ], 'http://localhost/login',
    '/beer redirected to login page when not logged in';

response_redirect_location_is  [ GET => '/regex/a' ], 'http://localhost/login',
    '/regex/a redirected to login page when not logged in';

# OK, now check we can't log in with fake details

response_status_is  [ 
    POST => '/login', { body => { username => 'foo', password => 'bar' } }
], 401, 'Login with fake details fails';

# ... and that we can log in with real details
response_status_is [
    POST => '/login', { body => { username => 'dave', password => 'beer' } }
], 302, 'Login with real details succeeds';


# Now we're logged in, check we can access stuff we should...

response_status_is [ GET => '/loggedin' ], 200,
    'Can access /loggedin now we are logged in';


response_content_is [ GET => '/loggedin' ], 'You are logged in',
    'Correct page content while logged in, too';;

response_content_is [ GET => '/name' ], 'Hello, David Precious',
    'Logged in user details via logged_in_user work';


response_content_is [ GET => '/roles' ], 'BeerDrinker,Motorcyclist',
    'Correct roles for logged in user';


# Check we can request something which requires a role we have....
response_status_is [ GET => '/beer' ], 200,
    'We can request a route (/beer) requiring a role we have...';

# And also a route declared as a regex (this should be no different, but
# melmothX was seeing issues with routes not requiring login when they should...
response_status_is [ GET => '/regex/a' ], 200,
    "We can request a regex route when logged in";

# ... but can't request something requiring a role we don't have
response_redirect_location_is  [ GET => '/piss' ],
    'http://localhost/login/denied',
    "We cannot request a route requiring a role we don't have";

# Check the realm we authenticated against is what we expect
response_content_is [ GET => '/realm' ], 'config1',
    'Authenticated against expected realm';

# Now, log out
response_status_is [
    POST => '/logout', {},
], 200, 'Logging out returns 200';


# Check we can't access protected pages now we logged out:
response_redirect_location_is  [ GET => '/loggedin' ], 'http://localhost/login',
    '/loggedin redirected to login page after logging out';

response_redirect_location_is  [ GET => '/beer' ], 'http://localhost/login',
'/beer redirected to login page after logging out';

# OK, log back in, this time as a user from the second realm
response_status_is [
    POST => '/login', { body => { username => 'burt', password => 'bacharach' } }
], 302, 'Login as user from second realm succeeds';

# And that now we're logged in again, we can access protected pages
response_status_is [ GET => '/loggedin' ], 200,
    'Can access /loggedin now we are logged in again';

# And that the realm we authenticated against is what we expect
response_content_is [ GET => '/realm' ], 'config2',
    'Authenticated against expected realm';

# Now, log out again
response_status_is [
    POST => '/logout', {},
], 200, 'Logged out again';


# Now check we can log in as a user whose password is stored hashed:
response_status_is [
    POST => '/login', { 
        body => { username => 'hashedpassword', password => 'password' } 
    }
], 302, 'Login as user with hashed password succeeds';

# And that now we're logged in again, we can access protected pages
response_status_is [ GET => '/loggedin' ], 200,
    'Can access /loggedin now we are logged in again';

# Check that the redirect URL can be set when logging in
response_redirect_location_is(
    [
        POST => '/login', {
            body => { 
                username => 'dave',
                password => 'beer',
                return_url => '/foobar',
            },
        },
    ],
    'http://localhost/foobar',
    'Redirect after login to given return_url works',
);




done_testing();


