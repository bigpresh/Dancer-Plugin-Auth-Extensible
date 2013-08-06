package Dancer::Plugin::Auth::Extensible::Provider::Example;

use strict;
use base "Dancer::Plugin::Auth::Extensible::Provider::Base";

# A more sensible provider would be likely to get this information from e.g. a
# database (or LDAP, or...) rather than hardcoding it.  This, however, is an
# example.
sub users {
    return {
        'dave' => {
            name     => 'David Precious',
            password => 'beer',
            roles    => [ qw(Motorcyclist BeerDrinker) ],
        },
        'bob' => {
            name     => 'Bob The Builder',
            password => 'canhefixit',
            roles    => [ qw(Fixer) ],
        },
    };
}

=head1 NAME 

Dancer::Plugin::Auth::Extensible::Example - example authentication provider


=head1 DESCRIPTION

This class is intended as an example of what an authentication provider class
should do.  It is not intended for serious use (clearly).

See L<Dancer::Plugin::Auth::Extensible> for details on how to use the
authentication framework, including how to pick a more useful authentication
provider.

However, if you just want to test the framework, or want an example to work from
to build your own authentication provider class, this may be of use.

=cut

=head1 Class methods

=over

=item authenticate_user

Given the username and password entered by the user, return true if they are
authenticated, or false if not.

=cut

sub authenticate_user {
    my ($self, $username, $password) = @_;
    my $user_details = $self->get_user_details($username) or return;
    return $self->match_password($password, $user_details->{password});
}

=item get_user_details

Given a username, return details about the user.  The details returned will vary
depending on the provider; some providers may be able to return various data
about the user, some may not, depending on the authentication source.

Details should be returned as a hashref.

=cut

sub get_user_details {
    my ($self, $username) = @_;

    return $self->users->{lc $username};
}

=item get_user_roles

Given a username, return a list of roles that user has.

=back

=cut

sub get_user_roles {
    my ($self, $username) = @_;

    my $user_details = $self->get_user_details($username) or return;
    return $user_details->{roles};
}



1;

