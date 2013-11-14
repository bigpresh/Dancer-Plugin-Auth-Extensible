package Dancer::Plugin::Auth::Extensible::Provider::LDAP;

use strict;
use base "Dancer::Plugin::Auth::Extensible::Provider::Base";
use Net::LDAP;
use Dancer qw(warning);

=head1 NAME 

Dancer::Plugin::Auth::Extensible::LDAP - LDAP authentication provider


=head1 DESCRIPTION

This class is a generic LDAP authentication provider.

See L<Dancer::Plugin::Auth::Extensible> for details on how to use the
authentication framework.

This provider requires the following parameters in it's config file:

=over

=item * server

The LDAP server url. 

=item * basedn

The base dn user for all search queries (e.g. 'dc=ofosos,dc=org').

=item * authdn

This must be the distinguished name of a user capable of binding to
and reading the directory (e.g. 'cn=Administrator,cn=users,dc=ofosos,dc=org').

=item * password

The password of above named user

=item * usergroup

The group where users are to be found (e.g. 'cn=users,dc=ofosos,dc=org')

=item * roles

This is a comma separated list of LDAP group objects that are to be queried.

=back

=cut

=head1 Class methods

=over

=item authenticate_user

Given the sAMAccountName and password entered by the user, return true if they are
authenticated, or false if not.

=cut

sub authenticate_user {
    my ($self, $username, $password) = @_;

    my $settings = $self->realm_settings;

    my $ldap = Net::LDAP->new($settings->{server}) or die "$!";

    my $mesg = $ldap->bind(
        "cn=" . $username . "," . $settings->{usergroup},
        password => $password);

    $ldap->unbind;
    $ldap->disconnect;

    return not $mesg->is_error;
}

=item get_user_details

Given a sAMAccountName return the common name (cn), distinguished name (dn) and
user principal name (userPrincipalName) in a hash ref.

=cut

sub get_user_details {
    my ($self, $username) = @_;

    my $settings = $self->realm_settings;

    my $ldap = Net::LDAP->new($settings->{server}) or die "$@";

    my $mesg = $ldap->bind(
        $settings->{authdn},
        password => $settings->{password});

    if ($mesg->is_error) {
        warning($mesg->error);
    }

    $mesg = $ldap->search(
        base => $settings->{basedn},
        filter => "(&(objectClass=user)(sAMAccountName=" . $username . "))",
        );

    if ($mesg->is_error) {
        warning($mesg->error);
    }

    my @extract = qw(cn dn name userPrincipalName sAMAccountName);
    my %props = ();

    if ($mesg->entries > 0) {
        foreach my $ex (@extract) {
            $props{$ex} = $mesg->entry(0)->get_value($ex);
        }
    } else {
        warning("Error finding user details.");
    } 

    $ldap->unbind;
    $ldap->disconnect; 

    return \%props;
}

=item get_user_roles

Given a sAMAccountName, return a list of roles that user has.

=cut

sub get_user_roles {
    my ($self, $username) = @_;

    my $settings = $self->realm_settings;

    my $ldap = Net::LDAP->new($settings->{server}) or die "$@";

    my $mesg = $ldap->bind(
        $settings->{authdn},
        password => $settings->{password});

    if ($mesg->is_error) {
        warning($mesg->error);
    }

    my @relevantroles = split /,/, $settings->{roles};
    my @roles = ();

    foreach my $role (@relevantroles) {
        $mesg = $ldap->search(
            base => $settings->{basedn},
            filter => "(&(objectClass=user)(sAMAccountName=" . $username . ")(memberof=cn=". $role . "," . $settings->{usergroup} . "))",
            );
        if ($mesg->is_error) {
            warning($mesg->error);
        }
        if ($mesg->entries > 0) {
            push @roles, $role;
        }
    }

    $ldap->unbind;
    $ldap->disconnect;

    if (@roles == 0) {
        warning($settings->{roles});
    }

    return \@roles;
}

=back

=cut


1;

