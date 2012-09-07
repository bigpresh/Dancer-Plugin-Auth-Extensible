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
    'We can request a route requiring a role we have...';

# ... but can't request something requiring a role we don't have
response_redirect_location_is  [ GET => '/piss' ],
    'http://localhost/login/denied',
    "We cannot request a route requiring a role we don't have";





