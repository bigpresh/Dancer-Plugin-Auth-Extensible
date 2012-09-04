package Dancer::Plugin::Auth::Extensible;

use warnings;
use strict;

our $VERSION = '0.01';

=head1 NAME

Dancer::Plugin::Auth::Extensible - extensible authentication framework for Dancer apps


=head1 SYNOPSIS

Configure the plugin to use the authentication class you wish to use.

See for example L<Dancer::Plugin::Auth::Extensible::Provider::Database>.

    plugins:
        auth:
            extensible:
                provider: Database
                table: users


Define that a user must be logged in to access a route:

    get '/secret' => sub :RequireRole(Confidant) { tell_secrets(); };

Define that a user must be logged in to access a route - and find out who is
logged in with the C<logged_in_user> keyword:

    get '/users' => sub :RequireLogin {
        my $user = logged_in_user;
        return "Hi there, $user->{username}";
    };



=head1 Controlling access to routes

Subroutine attributes are used to indicate that a route requires a login, or a
specific role.

Multiple roles can easily be provided as a space-separated list, for example:

    get '/user/:user_id' => sub :RequireRole(Admin TeamLeader) {
        ...
    };

If you only care that the user be logged in, use the RequireLogin attribute
instead:

    get '/dashboard' => sub :RequireLogin { .... };

If the user is not logged in, the C<login_needed> hook will fire; code using
that hook can return a redirect to a login page URL, or generate and return a
login page.

If no hook issues a redirection or response, the default is to output a simple
built-in login page, allowing you to immediately start using this framework.

Similarly, if the user is logged in, but does not have a suitable role, the
C<permission_denied> hook will fire; code using that hook can return a redirect
or a response.  If no code does so, a default "permission denied" response will
be issued.


=head1 AUTHOR

David Precious, C<< <davidp at preshweb.co.uk> >>

=head1 BUGS / FEATURE REQUESTS

This is an early version; there may still be bugs present or features missing.

This is developed on GitHub - please feel free to raise issues or pull requests!




=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Precious.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Dancer::Plugin::Auth::Extensible
