package Dancer::Plugin::Auth::Extensible::Provider::Unix;

use strict;
use base 'Dancer::Plugin::Auth::Extensible::Provider::Base';
use Authen::Simple::PAM;
use Unix::Passwd::File;

=head1 NAME

Dancer::Plugin::Auth::Extensible::Unix - authenticate *nix system accounts

=head1 DESCRIPTION

An authentication provider for L<Dancer::Plugin::Auth::Extensible> which
authenticates Linux/Unix system accounts.

Uses L<Unix::Passwd::File> to read user details, and L<Authen::Simple::PAM> to
perform authentication via PAM.

The C<get_user_details> call for this provider will return information from the
C<passwd> file - expect C<gecos>, C<gid>, C<uid>, C<home>, C<shell>, C<uid>.

Unix group membership is used as a reasonable facsimile for roles - this seems
sensible.

=cut

sub authenticate_user {
    my ($class, $username, $password) = @_;
    my $pam = Authen::Simple::PAM->new( service => 'login' );
    return $pam->authenticate($username, $password);
}
    

sub get_user_details {
    my ($class, $username) = @_;

    my $result = Unix::Passwd::File::get_user(
        user => $username
    );
    return if $result->[0] != 200;
    return $result->[2];
}

sub get_user_roles {
    my ($class, $username) = @_;
    my $result = Unix::Passwd::File::get_user_groups(user => $username);
    return if $result->[0] != 200;
    return $result->[2];
}

1;

