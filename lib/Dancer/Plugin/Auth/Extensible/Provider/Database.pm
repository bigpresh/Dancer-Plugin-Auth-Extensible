package Dancer::Plugin::Auth::Extensible::Provider::Database;

use strict;
use base 'Dancer::Plugin::Auth::Extensible::Provider::Base';
use Dancer::Plugin::Database;


=head1 NAME 

Dancer::Plugin::Auth::Extensible::Database - authenticate via a database


=head1 DESCRIPTION

This class is an authentication provider designed to authenticate users against
a database, using L<Dancer::Plugin::Database> to access a database.

L<Crypt::SaltedHash> is used to handle hashed passwords securely; you wouldn't
want to store plain text passwords now, would you?  (If your answer to that is
yes, please reconsider; you really don't want to do that, when it's so easy to
do things right!)

See L<Dancer::Plugin::Database> for how to configure a database connection
appropriately; see the L</CONFIGURATION> section below for how to configure this
authentication provider with database details.

See L<Dancer::Plugin::Auth::Extensible> for details on how to use the
authentication framework, including how to pick a more useful authentication
provider.


=head1 CONFIGURATION

This provider tries to use sensible defaults, so you may not need to provide
much configuration if your database tables look similar to those in the
L</SUGGESTED SCHEMA> section below.

The most basic configuration, assuming defaults for all options:

    plugins:
        Auth::Extensible:
            provider: 'Database'

(You would still need to have provided suitable database connection details to
L<Dancer::Plugin::Database>, of course;  see the docs for that plugin for full
details, but it could be as simple as, e.g.:

    plugins:
        Auth::Extensible:
            provider: 'Database'
        Database:
            driver: 'SQLite'
            database: 'test.sqlite'


A full example showing all options:

    plugins:
        Auth::Extensible:
            provider: 'Database'
            # optionally set DB connection name to use (see named connections in
            # Dancer::Plugin::Database docs)
            db_connection_name: 'foo'

            # Optionally disable roles support, if you only want to check for
            # successful logins but don't need to use role-based access:
            disable_roles: 1

            # optionally specify names of tables if they're not the defaults
            # (defaults are 'users', 'roles' and 'user_roles')
            users_table: 'users'
            roles_table: 'roles'
            user_roles_table: 'user_roles'

            # optionally set the column names (see the SUGGESTED SCHEMA section
            # below for the default names; if you use them, they'll Just Work)
            users_id_column: 'id'
            users_username_column: 'username'
            users_password_column: 'password'
            roles_id_column: 'id'
            roles_role_column: 'role'
            user_roles_user_id_column: 'user_id'
            user_roles_role_id_column: 'roles_id'



=head1 SUGGESTED SCHEMA

If you use a schema similar to the examples provided here, you should need
minimal configuration to get this authentication provider to work for you.

The examples given here should be MySQL-compatible; minimal changes should be
required to use them with other database engines.

=head2 users table

You'll need a table to store user accounts in, of course.  A suggestion is
something like:

    CREATE TABLE users (
        id       INTEGER     AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(32) NOT NULL       UNIQUE KEY,
        password VARCHAR(32) NOT NULL
    );

You will quite likely want other fields to store e.g. the user's name, email
address, etc; all columns from the users table will be returned by the
C<logged_in_user> keyword for your convenience.

=head2 roles table

You'll need a table to store a list of available roles in (unless you're not
using roles - in which case, disable role support (see the L</CONFIGURATION>
section).

    CREATE TABLE roles (
        id    INTEGER     AUTO_INCREMENT PRIMARY KEY,
        role  VARCHAR(32) NOT NULL
    );

=head2 user_roles table

Finally, (unless you've disabled role support)  you'll need a table to store
user <-> role mappings (i.e. one row for every role a user has; so adding 
extra roles to a user consists of adding a new role to this table).  It's 
entirely up to you whether you use an "id" column in this table; you probably
shouldn't need it.

    CREATE TABLE user_roles (
        user_id  INTEGER  NOT NULL,
        role_id  INTEGER  NOT NULL,
        UNIQUE KEY user_role (user_id, role_id)
    );

If you're using InnoDB tables rather than the default MyISAM, you could add a
foreign key constraint for better data integrity; see the MySQL documentation
for details, but a table definition using foreign keys could look like:

    CREATE TABLE user_roles (
        user_id  INTEGER, FOREIGN KEY (user_id) REFERENCES users (id),
        role_id  INTEGER, FOREIGN_KEY (role_id) REFERENCES roles (id),
        UNIQUE KEY user_role (user_id, role_id)
    ) ENGINE=InnoDB;


=cut


sub authenticate_user {
    my ($self, $username, $password) = @_;

    # Look up the user:
    my $user = $self->get_user_details($username);
    return unless $user;

    # OK, we found a user, let match_password (from our base class) take care of
    # working out if the password is correct

    my $settings = $self->realm_settings;
    my $password_column = $settings->{users_password_column} || 'password';
    return $self->match_password($password, $user->{$password_column});
}


# Return details about the user.  The user's row in the users table will be
# fetched and all columns returned as a hashref.
sub get_user_details {
    my ($self, $username) = @_;
    return unless defined $username;

    my $settings = $self->realm_settings;

    # Get our database handle and find out the table and column names:
    my $database = database($settings->{db_connection_name})
        or die "No database connection";

    my $users_table     = $settings->{users_table}     || 'users';
    my $username_column = $settings->{users_username_column} || 'username';
    my $password_column = $settings->{users_password_column} || 'password';

    # Look up the user, 
    my $user = $database->quick_select(
        $users_table, { $username_column => $username }
    );
    if (!$user) {
        debug("No such user $username");
        return;
    } else {
        return $user;
    }
}

sub get_user_roles {
    my ($self, $username) = @_;

    my $settings = $self->realm_settings;
    # Get our database handle and find out the table and column names:
    my $database = database($settings->{db_connection_name});

    # Get details of the user first; both to check they exist, and so we have
    # their ID to use.
    my $user = $self->get_user_details($username)
        or return;

    # Right, fetch the roles they have.  There's currently no support for
    # JOINs in Dancer::Plugin::Database, so we'll need to do this query
    # ourselves - so we'd better take care to quote the table & column names, as
    # we're going to have to interpolate them.  (They're coming from our config,
    # so should be pretty trustable, but they might conflict with reserved
    # identifiers or have unacceptable characters to not be quoted.)
    # Because I've tried to be so flexible in allowing the user to configure
    # table names, column names, etc, this is going to be fucking ugly.
    # Seriously ugly.  Clear bag of smashed arseholes territory.


    my $roles_table = $database->quote_identifier(
        $settings->{roles_table} || 'roles'
    );
    my $roles_role_id_column = $database->quote_identifier(
        $settings->{roles_id_column} || 'id'
    );
    my $roles_role_column = $database->quote_identifier(
        $settings->{roles_role_column} || 'role'
    );


    my $user_roles_table = $database->quote_identifier(
        $settings->{user_roles_table} || 'user_roles'
    );
    my $user_roles_user_id_column = $database->quote_identifier(
        $settings->{user_roles_user_id_column} || 'user_id'
    );
    my $user_roles_role_id_column = $database->quote_identifier(
        $settings->{user_roles_role_id_column} || 'role_id'
    );

    # Yes, there's SQL interpolation here; yes, it makes me throw up a little.
    # However, all the variables used have been quoted appropriately above, so
    # although it might look like a camel's arsehole, at least it's safe.
    my $sql = <<QUERY;
SELECT $roles_table.$roles_role_column
FROM $user_roles_table
JOIN $roles_table 
  ON $roles_table.$roles_role_id_column 
   = $user_roles_table.$user_roles_role_id_column
WHERE $user_roles_table.$user_roles_user_id_column = ?
QUERY

    my $sth = $database->prepare($sql)
        or die "Failed to prepare query - error: " . $database->err_str;

    $sth->execute($user->{$settings->{users_id_column} || 'id'});

    my @roles;
    while (my($role) = $sth->fetchrow_array) {
        push @roles, $role;
    }

    return \@roles;

    # If you read through this, I'm truly, truly sorry.  This mess was the price
    # of making things so configurable.  Send me your address, and I'll send you
    # a complementary fork to remove your eyeballs with as way of apology.
    # If I can bear to look at this code again, I think I might seriously
    # refactor it and use Template::Tiny or something on it.  Or Acme::Bleach.
}



1;
