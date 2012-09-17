package Dancer::Plugin::Auth::Extensible::Provider::Base;

# Base class for authentication providers; provides a constructor and handles
# remembering the realm-specific settings we're using.
#
# (There could be multiple realms, using the same provider but differently
# configured, so each realm will have its own auth provider instance.)

sub new {
    my ($class, $realm) = @_;
    my $self = {
        realm_settings => $realm_settings,
    };
    return bless $self => $class;
}


