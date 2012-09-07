package t::lib::TestApp;

use Dancer;



set session => 'simple';
set plugins => { 'Auth::Extensible' => { provider => 'Example' } };

use Dancer::Plugin::Auth::Extensible;
no warnings 'uninitialized';


get '/' => sub {
    "Index always accessible";
};

get '/loggedin' => sub :RequireLogin {
    "You are logged in";
};

get '/name' => sub :RequireLogin {
    return "Hello, " . logged_in_user->{name};
};

get '/roles' => sub :RequireLogin {
    return join ',', sort @{ user_roles() };
};

get '/beer' => sub :RequireRole(BeerDrinker) {
    "You can have a beer";
};

get '/piss' => sub :RequireRole(BearGrylls) {
    "You can drink piss";
};



1;
