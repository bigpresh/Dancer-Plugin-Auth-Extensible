package t::lib::TestApp;

use Dancer;



set session => 'simple';
set plugins => { 'Auth::Extensible' => { provider => 'Example' } };

use Dancer::Plugin::Auth::Extensible;
no warnings 'uninitialized';


get '/' => sub {
    "Index always accessible";
};

get '/loggedin' => require_login sub  {
    "You are logged in";
};

get '/name' => require_login sub {
    return "Hello, " . logged_in_user->{name};
};

get '/roles' => require_login sub {
    return join ',', sort @{ user_roles() };
};

get '/roles/:user' => require_login sub {
    my $user = param 'user';
    return join ',', sort @{ user_roles($user) };
};

get '/roles/:user/:realm' => require_login sub {
    my $user = param 'user';
    my $realm = param 'realm';
    return join ',', sort @{ user_roles($user, $realm) };
};

get '/realm' => require_login sub {
    return session->{logged_in_user_realm};
};

get '/beer' => require_role BeerDrinker => sub {
    "You can have a beer";
};

get '/piss' => require_role BearGrylls => sub {
    "You can drink piss";
};

get '/piss/regex' => require_role qr/beer/i => sub {
    "You can drink piss now";
};

get '/anyrole' => require_any_role ['Foo','BeerDrinker'] => sub {
    "Matching one of multiple roles works";
};

get '/allroles' => require_all_roles ['BeerDrinker', 'Motorcyclist'] => sub {
    "Matching multiple required roles works";
};

get qr{/regex/(.+)} => require_login sub {
    return "Matched";
};

get '/testcaching' => sub {
    # See how many times the provider has been asked about a user
    my $c1 = $Dancer::Plugin::Auth::Extensible::Provider::Example::users_access_count;
    my $user = logged_in_user();
    my $c2 = $Dancer::Plugin::Auth::Extensible::Provider::Example::users_access_count;
    $user = logged_in_user();
    my $c3 = $Dancer::Plugin::Auth::Extensible::Provider::Example::users_access_count;
    return "$c1:$c2:$c3";
};


1;
