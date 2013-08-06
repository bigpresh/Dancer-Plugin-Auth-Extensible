package t::ldap::LDAPTestApp;

use Dancer;


set session => 'simple';
set plugins => { 'Auth::Extensible' => { provider => 'LDAP' } };

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

get '/realm' => require_login sub {
    return session->{logged_in_user_realm};
};

get '/beer' => require_role Jever => sub {
    "You can have a beer";
};

get '/piss' => require_role Warsteiner => sub {
    "You can drink piss";
};

get '/anyrole' => require_any_role ['Jever','Warsteiner', 'Budvar'] => sub {
    "Matching one of multiple roles works";
};

get '/allroles' => require_all_roles ['Jever', 'Budvar'] => sub {
    "Matching multiple required roles works";
};

get qr{/regex/(.+)} => require_login sub {
    return "Matched";
};


1;
