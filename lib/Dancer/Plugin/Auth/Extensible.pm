package Dancer::Plugin::Auth::Extensible;

use warnings;
use strict;
use attributes;
use Dancer::Plugin;
use Dancer qw(:syntax);
use Scalar::Util qw(refaddr);

our $VERSION = '0.01';

my $settings = plugin_setting;

# We must export these to the caller to allow them to use any attributes:
use Exporter 'import';
our @EXPORT=qw(MODIFY_CODE_ATTRIBUTES FETCH_CODE_ATTRIBUTES);

=head1 NAME

Dancer::Plugin::Auth::Extensible - extensible authentication framework for Dancer apps

=head1 SYNOPSIS

Configure the plugin to use the authentication provider class you wish to use:

  plugins:
        Auth::Extensible:
            realms:
                users:
                    provider: Example
                    ....

Define that a user must be logged in and have the proper permissions to 
access a route:

    get '/secret' => sub :RequireRole(Confidant) { tell_secrets(); };

Define that a user must be logged in to access a route - and find out who is
logged in with the C<logged_in_user> keyword:

    get '/users' => sub :RequireLogin {
        my $user = logged_in_user;
        return "Hi there, $user->{username}";
    };

=head1 AUTHENTICATION PROVIDERS

For flexibility, this authentication framework uses simple authentication
provider classes, which implement a simple interface and do whatever is required
to authenticate a user.

For an example of how simple provider classes are, so you can build your own if
required or just try out this authentication framework plugin easily, 
see L<Dancer::Plugin::Auth::Extensible::Provider::Example>.

This framework supplies the following providers out-of-the-box:

=over 4

=item L<Dancer::Plugin::Auth::Extensible::Provider::Unix>

=item L<Dancer::Plugin::Auth::Extensible::Provider::Database>

=back

=head1 CONTROLLING ACCESS TO ROUTES

Subroutine attributes are used to indicate that a route requires a login, or a
specific role.

Multiple roles can easily be provided as a space-separated list, for example:

    get '/user/:user_id' => sub :RequireRole(Admin TeamLeader) {
        ...
    };

(The user will be granted access if they have any of the roles denoted.)

If you only care that the user be logged in, use the RequireLogin attribute
instead:

    get '/dashboard' => sub :RequireLogin { .... };

If the user is not logged in, they will be redirected to the login page URL to
log in.  Currently, the URL is C</login> - this may be made configurable.

=head2 Replacing the Default C< /login > and C< /login/denied > Routes

By default, the plugin adds a route to present a simple login form at that URL.
If you would rather add your own, set the C<no_default_pages> setting to a true
value, and define your own route which responds to C</login> with a login page.

If the user is logged in, but tries to access a route which requires a specific
role they don't have, they will be redirected to the "permission denied" page
URL, which is C</login/denied> - this may be made configurable later.

Again, by default a route is added to respond to that URL with a default page;
again, you can disable this by setting C<no_default_pages> and creating your
own.

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

=item user_has_role

Check if a user has the role named.

By default, the currently-logged-in user will be checked, so you need only name
the role you're looking for:

    if (user_has_role('BeerDrinker')) { pour_beer(); }

You can also provide the username to check; 

    if (user_has_role($user, $role)) { .... }

=cut

sub user_has_role {
    my ($username, $want_role);
    if (@_ == 2) {
        ($username, $want_role) = @_;
    } else {
        $username  = session 'logged_in_user';
        $want_role = shift;
    }

    return unless defined $username;

    my $roles = user_roles($username);

    for my $has_role (@$roles) {
        return 1 if $has_role eq $want_role;
    }

    return 0;
}
register user_has_role => \&user_has_role;

=item user_roles

Returns a list of the roles of a user.

By default, roles for the currently-logged-in user will be checked;
alternatively, you may supply a username to check.

Returns a list or arrayref depending on context.

=cut

sub user_roles {
    my ($username) = @_;
    $username = session 'logged_in_user' unless defined $username;

    my $roles = auth_provider()->get_user_roles($username);
    return unless defined $roles;
    return wantarray ? @$roles : $roles;
}
register user_roles => \&user_roles;


=back

=head2 COMPLETE SAMPLE CONFIGURATION

In your application's configuation file:

  plugins:
    session: simple
    plugins:
        Auth::Extensible:
            provider: Database
            # optionally set DB connection name to use (see named connections in
            # Dancer::Plugin::Database docs)
            db_connection_name: 'foo'

            # Set to 1 if you want to disable the use of roles (0 is default)
            disable_roles: 0

            # Set these if you use something other than the default table
            # names
            users_table: 'users'
            roles_table: 'roles'
            user_roles_table: 'user_roles'

            # Set these if you use something other than the default column
            # names 
            users_id_column: 'id'
            users_username_column: 'username'
            users_password_column: 'password'
            roles_id_column: 'id'
            roles_role_column: 'role'
            user_roles_user_id_column: 'user_id'
            user_roles_role_id_column: 'roles_id'

B< Please note > that you B< must > have a session provider configured.  The authentication
framework requires sessions in order to track information about the currently logged in user.
Please see L< Dancer::Session > for information on how to configure session management
within your application.

=cut

# Loads the auth provider (if it's not already loaded) and returns the package
# name.
sub auth_provider {
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
    my $roles_required = get_attribs_by_type(
        'RequireRole', $route_handler->code
    );
    
    # If we don't need to be logged in for this route, we need do no more:
    return if (!defined($requires_login) && !defined($roles_required));

    my $user = logged_in_user();
    
    if (!$user) {
        execute_hook('login_required', $route_handler);
        # TODO: check if code executed by that hook set up a response
        return redirect '/login';
    }

    # OK, we're logged in as someone; if no specific roles are required, that's
    # the end of the checking needed
    return unless defined $roles_required;

    # OK, find out what roles this user has; if they have one of the roles we're
    # looking for, they're OK
    my $user_roles = auth_provider()->get_user_roles(
        session 'logged_in_user'
    );

    my %acceptable_role = map { $_ => 1 } @$roles_required;

    for my $user_role (@$user_roles) {
        if ($acceptable_role{$user_role}) {
            return;
        }
    }

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


# Set up routes to serve default pages, if desired
if (!$settings->{no_default_pages}) {
    get '/login' => sub {
        status 401;
        return _default_login_page();
    };
    get '/login/denied' => sub {
        status 403;
        return _default_permission_denied_page();
    };
}

# Handle logging in...
post '/login' => sub {
    my $provider = auth_provider();
    if ($provider->authenticate_user(params->{username}, params->{password})) {
        session logged_in_user => params->{username};
        redirect params->{return_url} || '/';
    } else {
        vars->{login_failed}++;
        forward '/login', { login_failed => 1 }, { method => 'GET' };
    }
};

sub _default_permission_denied_page {
    return <<PAGE
<h1>Permission Denied</h1>

<p>
Sorry, you're not allowed to access that page.
</p>
PAGE
}

sub _default_login_page {
    my $login_fail_message = vars->{login_failed}
        ? "<p>LOGIN FAILED</p>"
        : "";
    return <<PAGE;
<h1>Login Required</h1>

<p>
You need to log in to continue.
</p>

$login_fail_message

<form method="post">
<label for="username">Username:</label>
<input type="text" name="username" id="username">
<br />
<label for="password">Password:</label>
<input type="password" name="password" id="password">
<br />
<input type="submit" value="Login">
</form>
PAGE
}
=head1 AUTHOR

David Precious, C<< <davidp at preshweb.co.uk> >>


=head1 BUGS / FEATURE REQUESTS

This is an early version; there may still be bugs present or features missing.

This is developed on GitHub - please feel free to raise issues or pull requests
against the repo at:
L<https://github.com/bigpresh/Dancer-Plugin-Auth-Extensible>



=head1 ACKNOWLEDGEMENTS

None yet - why not help out and get your name here? :)


=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Precious.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Dancer::Plugin::Auth::Extensible
