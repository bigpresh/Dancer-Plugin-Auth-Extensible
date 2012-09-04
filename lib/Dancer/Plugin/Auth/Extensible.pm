package Dancer::Plugin::Auth::Extensible;

use warnings;
use strict;
use attributes;
use Dancer::Plugin;
use Dancer qw(:syntax);
use Scalar::Util qw(refaddr);

our $VERSION = '0.01';

# We must export these to the caller to allow them to use any attributes:
use Exporter 'import';
our @EXPORT=qw(MODIFY_CODE_ATTRIBUTES FETCH_CODE_ATTRIBUTES);

=head1 NAME

Dancer::Plugin::Auth::Extensible - extensible authentication framework for Dancer apps


=head1 SYNOPSIS

Configure the plugin to use the authentication class you wish to use.

See for example L<Dancer::Plugin::Auth::Extensible::Provider::Database>.

    plugins:
        auth:
            extensible:
                provider: Example


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

=head2 Keywords

=over

=item logged_in_user

Returns a hashref of details of the currently logged-in user, if there is one.

The details you get back will depend upon the authentication provider in use.

=cut

sub logged_in_user {
    if (my $user = session 'logged_in_user') {
        my $provider = auth_provider();
        return $provider->get_user_details($user);
    } else {
        return;
    }
}
register logged_in_user => \&logged_in_user;

=back

=cut


# Loads the auth provider (if it's not already loaded) and returns the package
# name.
sub auth_provider {
    my $settings = plugin_setting;
    my $provider = $settings->{provider}
        or die "No provider configured - consult documentation for "
            . __PACKAGE__;

    if ($provider !~ /::/) {
        $provider = __PACKAGE__ . "::Provider::$provider";
    }
    Dancer::ModuleLoader->load($provider)
        or die "Cannot load provider $provider";

    return $provider;
}
register_hook qw(login_required permission_denied);
register_plugin versions => qw(1 2);

# Hook to catch routes about to be executed, and check for attributes telling us
# we need to make sure the user is auth'd

hook before => sub {
    my $route_handler = shift || return;

    my $requires_login = get_attribs_by_type(
        'RequireLogin', $route_handler->code
    );
    if (defined $requires_login && !logged_in_user) {
        # TODO: fire hooks, print default message
        execute_hook('login_required', $route_handler);
        
        # TODO: see if a response is set
        return redirect '/login';
    }

    my $roles_required = get_attribs_by_type(
        'RequireRole', $route_handler->code
    );
    return unless defined $roles_required;

    execute_hook(
        'permission_denied',
        $route_handler,
        $roles_required
    );

    # TODO: see if a response is set
    return redirect '/login/denied';
};


# Boilerplate to support attribute setting & fetching
my %attrs;
sub MODIFY_CODE_ATTRIBUTES {
    my ($package, $subref, @attrs) = @_;
    $attrs{ refaddr $subref } = \@attrs;
    return;
} 
sub FETCH_CODE_ATTRIBUTES {
    my ($package, $subref) = @_;
    my $attrs = $attrs{ refaddr $subref };
    return $attrs ? @$attrs : ();
}

sub get_attribs_by_type {
    my ($type, $coderef) = @_;
    return unless $coderef;

    warn "Want attributes for $coderef  - " . ref $coderef;

    # This voodoo was originally written by an evil bad man with a big beard;
    # I simply embraced and extended it, whilst midly fearing for my life.
    # Thus, blame him, not me.

    my @desired_attribs = grep { 
        /^$type(?:\([^)]*\))?$/ 
    } attributes::get($coderef);
    
    return if !@desired_attribs;

    # OK, we matched an attribute above; it might have been on its own (e.g. 
    # "LoginNeeded") or it might contain a list of values we need to return
    # (e.g. RequireRole(Foo Bar Baz)).
    # So, an empty arrayref is fine to return; it indicates we found the
    # desired attribute, but it had no values within parens.
    return [
        map {
            my $f = $_;
            # extract and split a white-space-delimited list wrapped in
            # parens with optional leading/trailing shitespace
            $f =~ s/^$type\(\s*([^)]*)\s*\)$/$1/;
            split(/\s+/, $f);
        } @desired_attribs
    ];
}
 

sub _default_permission_denied_page {
    return <<PAGE
<h1>Permission Denied</h1>

<p>
Sorry, you're not allowed to access that page.
</p>
PAGE
}

sub _default_login_page {
    return <<PAGE
<h1>Login Required</h1>

<p>
You need to log in to continue.
</p>

<form method="post">
Username: <input type="text" name="username">
<br />
Password: <input type="password" name="password">
<br />
<input type="submit" value="Login">
</form>
PAGE
}
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
