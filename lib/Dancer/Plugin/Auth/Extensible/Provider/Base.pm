package Dancer::Plugin::Auth::Extensible::Provider::Base;

use strict;
use Crypt::SaltedHash;

=head1 NAME

Dancer::Plugin::Auth::Extensible::Provider::Base

=head1 DESCRIPTION

Base class for authentication providers.  Provides a constructor which handles
receiving the realm settings and returning an instance of the provider.

Also provides secure password matching which automatically handles crypted
passwords via Crypt::SaltedHash.

Finally, provides the methods which providers must override with their
implementation, which will die if they are not overridden.

=cut

sub new {
    my ($class, $realm_settings) = @_;
    my $self = {
        realm_settings => $realm_settings,
    };
    return bless $self => $class;
}

sub realm_settings { shift->{realm_settings} || {} }


 
sub match_password {
    my ($self, $given, $correct) = @_;

    # TODO: perhaps we should accept a configuration option to state whether
    # passwords are crypted or not, rather than guessing by looking for the
    # {...} tag at the start.
    # I wanted to let it try straightforward comparison first, then try
    # Crypt::SaltedHash->validate, but that has a weakness: if a list of hashed
    # passwords got leaked, you could use the hashed password *as it is* to log
    # in, rather than cracking it first.  That's obviously Not Fucking Good.
    # TODO: think about this more.  This shit is important.  I'm thinking a
    # config option to indicate whether passwords are crypted - yes, no, auto
    # (where auto would do the current guesswork, and yes/no would just do as
    # told.)
    if ($correct =~ /^{.+}/) {
        # Looks like a crypted password starting with the scheme, so try to
        # validate it with Crypt::SaltedHash:
        return Crypt::SaltedHash->validate($correct, $given);
    } else {
        # Straightforward comparison, then:
        return $given eq $correct;
    }
}


# Install basic method placeholders which will blow up if the provider module
# did not implement their own version. 
{
    no strict 'refs';
    for my $method (qw(
        authenticate_user
        get_user_details
        get_user_roles
        ))
    {
        *$method = sub {
            die "$method was not implemented by provider " . __PACKAGE__;
        };
    }
}




1;

