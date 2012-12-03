package Dancer::Plugin::Auth::Extensible::Provider::Config;

use strict;
use base "Dancer::Plugin::Auth::Extensible::Provider::Base";

=head1 NAME 

Dancer::Plugin::Auth::Extensible::Config - example auth provider using app config


=head1 DESCRIPTION

This is a simple authentication provider which authenticates based on a list of
usernames, passwords (crypted, preferably - see below) and role specifications
provided in the realm definition in your app's config file.

This class is primarily intended as an example of what an authentication 
provider class should do; however, if you just want simple user authentication
with user details stored in your app's config file, it may well suit your needs.

See L<Dancer::Plugin::Auth::Extensible> for details on how to use the
authentication framework.

=head1 SYNOPSIS

In your app's C<config.yml>:

    plugins:
        Auth::Extensible:
            realms:
                config:
                    provider: Config
                    users:
                        -user: dave
                         pass: supersecret
                         roles:
                            - Developer
                            - Manager
                            - BeerDrinker
                        -user: bob
                         pass: '{SSHA}+2u1HpOU7ak6iBR6JlpICpAUvSpA/zBM'
                         roles:
                            - Tester

As you can see, you can define the usernames, passwords (please use crypted
passwords, RFC2307-style, not plain text (although plain text *is* supported,
but really not a good idea), and the roles for each user (if you're
not planning to use roles, omit the roles section from each user entirely).

=cut

sub authenticate_user {
    my ($self, $username, $password) = @_;
    my $user_details = $self->get_user_details($username) or return;
    return $self->match_password($password, $user_details->{pass});
}

# Just return the whole user definition from the config; this way any additional
# fields defined for users will just get passed through.
sub get_user_details {
    my ($self, $username) = @_;
    my ($user) = grep {
        $_->{user} eq $username 
    } @{ $self->realm_settings->{users} };
    return $user;
}

sub get_user_roles {
    my ($self, $username) = @_;

    my $user_details = $self->get_user_details($username) or return;
    return $user_details->{roles};
}

1;

