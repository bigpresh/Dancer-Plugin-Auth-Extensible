#!/usr/bin/perl

use Dancer;
use lib '../lib';
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

get '/secret' => require_login sub { "Need to be logged in" };

get '/beer' => require_any_role [qw(BeerDrinker HardDrinker)], sub {
    "Any drinker can get beer.";
};

get '/vodka' => require_role HardDrinker => sub {
    "Only hard drinkers get vodka";
};

get '/realm' => require_login sub {
    "You are logged in using realm: " . session->{logged_in_user_realm};
};
dance();
