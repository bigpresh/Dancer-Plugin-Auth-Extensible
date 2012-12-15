package t::lib::TestApp;

use Dancer;



set session => 'simple';
set plugins => { 'Auth::Extensible' => { provider => 'Example' } };

use Dancer::Plugin::Auth::Extensible;
no warnings 'uninitialized';


get '/' => sub {
    "Index always accessible";
};

get '/loggedin' => requires_login sub  {
    "You are logged in";
};

get '/name' => requires_login sub {
    return "Hello, " . logged_in_user->{name};
};

get '/roles' => requires_login sub {
    return join ',', sort @{ user_roles() };
};

get '/realm' => requires_login sub {
    return session->{logged_in_user_realm};
};

get '/beer' => requires_role BeerDrinker => sub {
    "You can have a beer";
};

get '/piss' => requires_role BearGrylls => sub {
    "You can drink piss";
};

get '/anyrole' => requires_any_role ['Foo','BeerDrinker'] => sub {
    "Matching one of multiple roles works";
};

get '/allroles' => requires_all_roles ['BeerDrinker', 'Motorcyclist'] => sub {
    "Matching multiple required roles works";
};

get qr{/regex/(.+)} => requires_login sub {
    return "Matched";
};


1;
