#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Dancer::Plugin::Auth::Extensible' ) || print "Bail out!
";
}

diag( "Testing Dancer::Plugin::Auth::Extensible $Dancer::Plugin::Auth::Extensible::VERSION, Perl $], $^X" );
