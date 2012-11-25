#!/usr/bin/perl

use Dancer;
use Dancer::Plugin::Auth::Extensible;

get '/' => sub {
    my $content = "<h1>Non-secret home page!</h1>";
    if (my $user = logged_in_user()) {
        $content .= "<p>Hi there, $user->{name}!</p>";
    } else {
        $content .= "<p>Why not log in?</p>";
    }

    $content .= <<LINKS;
<p><a href="/secret">Psst, wanna know a secret?</a></p>
<p><a href="/beer">Or maybe you want a beer</a></p>
<p><a href="/vodka">Or, a vodka?</a></p>
LINKS

    if (user_has_role('BeerDrinker')) {
        $content .= "<p>You can drink beer</p>";
    }
    if (user_has_role('WineDrinker')) {
        $content .= "<p>You can drink wine</p>";
    }

    return $content;
};

get '/secret' => sub :RequireLogin() { "Need to be logged in" };

get '/beer' => sub :RequireRole(BeerDrinker HardDrinker) {
    "Any drinker can get beer.";
};

get '/vodka' => sub :RequireRole(HardDrinker) {
    "Only hard drinkers get vodka";
};

get '/realm' => sub :RequiresLogin() {
    "You are logged in using realm: " . session->{logged_in_user_realm};
};
dance();
