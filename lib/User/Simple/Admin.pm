# $Id: Admin.pm,v 1.7 2005/06/15 17:17:10 gwolf Exp $
use warnings;
use strict;

package User::Simple::Admin;

=head1 NAME

User::Simple::Admin - User::Simple user administration

=head1 SYNOPSIS

  $ua = User::Simple::Admin->new($db, $user_table);

  $ua = User::Simple::Admin->create_rdbms_db_structure($db, $user_table);
  $ua = User::Simple::Admin->create_plain_db_structure($db, $user_table);
  $ok = User::Simple::Admin->has_db_structure($db, $user_table);

  %users = $ua->dump_users;

  $id = $ua->id($login);
  $login = $ua->login($id);
  $name = $ua->name($id);
  $level = $ua->level($id);

  $ok = $usr->set_login($id, $login);
  $ok = $usr->set_name($id, $name);
  $ok = $usr->set_level($id, $level);
  $ok = $usr->set_passwd($id, $passwd);
  $ok = $usr->clear_session($id);

  $id = $ua->new_user($login, $name, $passwd, $level);

  $ok = $ua->remove_user($id);

=head1 DESCRIPTION

User::Simple::Admin manages the administrative part of the User::Simple
modules - Please check L<User::Simple> for a general overview of these modules
and an explanation on what-goes-where.

User::Simple::Admin works as a regular administrator would: The module should
be instantiated only once for all of your users' administration, if possible,
and not instantiated once for each user (in contraposition to L<User::Simple>,
as it works from each of the users' perspective in independent instantiations).

Note also that User::Simple::Admin does b<not> perform the administrative user
checks - It is meant to be integrated to your system, and it is your system 
which should carry out all of the needed authentication checks.

=head2 CONSTRUCTOR

Administrative actions for User::Simple modules are handled through this
Admin object. To instantiate it:

  $ua = User::Simple::Admin->new($db, $user_table);

$db is an open connection to the database where the user data is stored.

$user_table is the name of the table that holds the users' data.

If we do not yet have the needed DB structure to store the user information,
we can use this class method as a constructor as well:

  $ua = User::Simple::Admin->create_rdbms_db_structure($db, $user_table);

  $ua = User::Simple::Admin->create_plain_db_structure($db, $user_table);

The first one should be used if your DBI handle ($db) points to a real RDBMS,
such as PostgreSQL or MySQL. In case you are using a file-based DBD (such as
DBD::XBase, DBD::DBM, DBD::CVS or any other which does not use a real RDBMS
for storage), use C<User::Simple::Admin-E<gt>create_plain_db_structure>
instead. What is the difference? In the first case, we will create a table
that has internal consistency checks - Some fields are declared NOT NULL, some
fields are declared UNIQUE, and the user ID is used as a PRIMARY KEY. This 
cannot, of course, be achieved using file-based structures, so the integrity
can only be maintained from within our scripts.

=head2 QUERYING FOR DATABASE READINESS

In order to check if the database is ready to be used by this module with the
specified table name, use the C<has_db_structure> class method:

  $ok = User::Simple::Admin->has_db_structure($db, $user_table);  

=head2 RETRIEVING THE SET OF USERS

  %users = $ua->dump_users;

Will return a hash with the data regarding the registered users, in the 
following form:

  ( $id1 => { level => $level1, name => $name1, login => $login1},
    $id2 => { level => $level2, name => $name2, login => $login2},
    (...) )

=head2 CREATING, QUERYING AND MODIFYING USERS

  $id = $ua->new_user($login, $name, $passwd, $level);

Creates a new user with the specified data. Returns the new user's ID.

  $ok = $ua->remove_user($id);

Removes the user specified by the ID.

  $id = $ua->id($login);
  $login = $ua->login($id);
  $name = $ua->name($id);
  $level = $ua->level($id);

Get the value of each of the mentioned attributes. Note that in order to get
the ID you can supply the login, every other method answers only to the ID. In
case you have the login and want to get the name, you should use 
C<$ua->name($ua->id($login));>

  $ok = $usr->set_login($id, $login);
  $ok = $usr->set_name($id, $name);
  $ok = $usr->set_passwd($id, $passwd);
  $ok = $usr->set_level($id, $level);

Modifies the requested attribute of the specified user, setting it to the new 
value.

=head2 SESSIONS

  $ok = $usr->clear_session($id);

Removes the session which the current user had open, if any.

Note that you cannot create a new session through this module - The only way of
creating a session is through the C<ck_login> method of L<User::Simple>.

=head1 DEPENDS ON

L<Digest::MD5>

=head1 SEE ALSO

L<User::Simple> for the regular user authentication routines (that is, to
use the functionality this module adimisters)

=head1 AUTHOR

Gunnar Wolf <gwolf@gwolf.org>

=head1 COPYRIGHT

Copyright 2005 Gunnar Wolf / Instituto de Investigaciones Económicas UNAM
This module is Free Software, it can be redistributed under the same terms
as Perl.

=cut

use Carp;
use Digest::MD5 qw(md5_hex);
use UNIVERSAL qw(isa);

######################################################################
# Constructor

sub new {
    my ($self, $class, $db, $table, $adm_level);
    $class = shift;
    $db = shift;
    $table = shift;
    $adm_level = shift;

    # Verify we got the right arguments
    unless (isa($db, 'DBI::db')) {
	carp "First argument must be a DBI connection";
	return undef;
    }

    if (defined $adm_level) {
	carp 'adm_level is considered deprecated and will be removed in'.
	    ' future releases.';
    } else {
	$adm_level = 1;
    }

    if ($adm_level !~ /^\d+$/) {
	carp "adm_level must be a non-negative integer";
	return undef;
    }

    # In order to check if the table exists, check if it consists only of
    # valid characters and query for a random user
    unless ($table =~ /^[\w\_]+$/) {
	carp "Invalid table name $table";
	return undef;
    }
    unless ($class->has_db_structure($db, $table)) {
	carp "Table $table does not exist or has wrong structure";
	carp "Use $class->create_db_structure first.";
	return undef;
    }

    $self = { db => $db, tbl => $table, adm_level => $adm_level };

    bless $self, $class;
    return $self;
}

######################################################################
# Creating the needed structure

sub create_rdbms_db_structure {
    my ($class, $db, $table, $sth);
    $class = shift;
    $db = shift;
    $table = shift;

    # Remember some DBD backends don't implement 'serial' - Use 'integer' and
    # some logic on our side instead
    unless ($sth = $db->prepare("CREATE TABLE $table (
            id serial PRIMARY KEY, 
            login varchar(100) NOT NULL UNIQUE,
            name varchar(100) NOT NULL,
            passwd char(32),
            level integer NOT NULL,
            session char(32) UNIQUE,
            session_exp varchar(20))") and $sth->execute) {
	carp "Could not create database structure using table $table";
	return undef;
    }

    return $class->new($db, $table);
}

sub create_plain_db_structure {
    my ($class, $db, $table, $sth);
    $class = shift;
    $db = shift;
    $table = shift;

    # Remember some DBD backends don't implement 'serial' - Use 'integer' and
    # some logic on our side instead
    unless ($sth = $db->prepare("CREATE TABLE $table (
            id integer, 
            login varchar(100),
            name varchar(100),
            passwd char(32),
            level integer,
            session char(32),
            session_exp varchar(20))") and $sth->execute) {
	carp "Could not create database structure using table $table";
	return undef;
    }

    return $class->new($db, $table);
}

sub has_db_structure {
    my ($class, $db, $table, $sth);
    $class = shift;
    $db = shift;
    $table = shift;

    # We check for the DB structure by querying for any given row. 
    # Yes, this method can fail if the needed fields exist but have the wrong
    # data, if the ID is not linked to a trigger and a sequence, and so on...
    # But usually, this check will be enough just to determine if we have the
    # structure ready.
    return 1 if ($sth=$db->prepare("SELECT id, login, name, passwd, level, 
                 session, session_exp FROM $table") and $sth->execute);
    return 0;
}

######################################################################
# Retrieving information

sub dump_users { 
    my ($self, $order, $sth, %users);
    $self = shift;

    unless ($sth = $self->{db}->prepare("SELECT id, login, name, level
            FROM $self->{tbl}") and $sth->execute) {
	carp 'Could not query for the user list';
	return undef;
    }

    while (my @row = $sth->fetchrow_array) {
	$users{$row[0]} = {login => $row[1],
			   name => $row[2],
			   level => $row[3],
			   is_admin => ($row[3] >= $self->{adm_level}) ? 1 : 0
			   };
    }

    return %users;
}

sub id { 
    my ($self, $login, $sth, $id);
    $self = shift;
    $login = shift;

    $sth = $self->{db}->prepare("SELECT id FROM $self->{tbl} WHERE login = ?");
    $sth->execute($login);

    ($id) = $sth->fetchrow_array;

    return $id;
}

sub login {
    my ($self, $id);
    $self = shift;
    $id = shift;
    return $self->_get_field($id, 'login'); 
}

sub name { 
    my ($self, $id);
    $self = shift;
    $id = shift;
    return $self->_get_field($id, 'name'); 
}

sub level {
    my ($self, $id);
    $self = shift;
    $id = shift;
    return $self->_get_field($id, 'level'); 
}

sub is_admin {
    my ($self, $id);
    $self = shift;
    $id = shift;
    carp "is_admin is deprecated! Please use level instead";
    return ($self->{adm_level} <= $self->level($id)) ? 1 : 0;
}

######################################################################
# Modifying information

sub set_login { 
    my ($self, $id, $new, $sth, $ret);
    $self = shift;
    $id = shift;
    $new = shift;

    if (my $used = $self->id($new)) {
	carp "The requested login is already used (ID $used).";
	return undef;
    }

    return $self->_set_field($id, 'login', $new);
}

sub set_name { 
    my ($self, $id, $new);
    $self = shift;
    $id = shift;
    $new = shift;
    return $self->_set_field($id, 'name', $new);
}

sub set_level {
    my ($self, $id, $new);
    $self = shift;
    $id = shift;
    $new = shift;
    return $self->_set_field($id, 'level', $new);
}

sub set_admin { 
    my ($self, $id);
    $self = shift;
    $id = shift;
    carp "set_admin is deprecated! Please use level instead";
    return $self->set_level($id, $self->{adm_level});
}

sub unset_admin { 
    my ($self, $id);
    $self = shift;
    $id = shift;
    carp "unset_admin is deprecated! Please use level instead";
    return $self->set_level($id, 0);
}

sub set_passwd { 
    my ($self, $id, $new, $crypted, $sth);
    $self = shift;
    $id = shift;
    $new = shift;

    $crypted = md5_hex($new, $id);

    return $self->_set_field($id, 'passwd', $crypted);
}

sub clear_session {
    my ($self, $id);
    $self = shift;
    $id = shift;
    return ($self->_set_field($id,'session','') && 
	    $self->_set_field($id, 'sesson_exp', ''));
}

######################################################################
# User creation and removal

sub new_user { 
    my ($self, $login, $name, $passwd, $level, $id, $db, $orig_state, 
	$has_transact);
    $self = shift;
    $login = shift;
    $name = shift;
    $passwd = shift;
    $level = shift || 0; # Don't whine on undef

    # We will use the database handler over and over - Get a shortcut.
    $db = $self->{db};

    # If available, we will do all this work inside a transaction. Sadly, not
    # every DBD provides such a facility - By trying to begin_work and
    # then commit on an empty transaction, we can check if this DBD does 
    # provide it. 
    eval { 
	$db->begin_work; 
	$db->commit;
    };
    $has_transact = $@ ? 0 : 1;

    $orig_state = $db->{RaiseError};
    eval {
	my ($sth);
	$db->begin_work if $has_transact;
	$db->{RaiseError} = 1;

	# Not all DBD backends implement the 'serial' datatype - We use a
	# simple integer, and we just move the 'serial' logic to this point,
	# the only new user creation area. 
	# Yes, this could lead to a race condition and to the attempt to insert
	# two users with the same ID - We have, however, the column as a 
	# 'primary key'. Any DBD implementing unicity will correctly fail. 
	# And... Well, nobody expects too high trust from a DBD backend which
	# does not implement unicity, right? :)
	$sth = $db->prepare("SELECT id FROM $self->{tbl} ORDER BY
            id desc");
	$sth->execute;
	($id) = $sth->fetchrow_array;
	$id++;

	$sth = $db->prepare("INSERT INTO $self->{tbl} (id, login, name,
            level) VALUES (?, ?, ?, ?)");
	$sth->execute($id, $login, $name, $level);

	# But just to be sure, lets retreive the ID from the login.
	$id = $self->id($login);
	$self->set_passwd($id, $passwd);

	$db->commit if $has_transact;
	$db->{RaiseError} = $orig_state;
    };
    if ($@) {
	if ($has_transact) {
	    $db->rollback;
	} else {
	    carp 'User creation was not successful. This DBD does not support'.
		' transactions - You might have a half-created user!';
	}
	$db->{RaiseError} = $orig_state;
	carp "Could not create specified user";
	return undef;
    }
    return $id;
}

sub remove_user { 
    my ($self, $id, $sth);
    $self = shift;
    $id = shift;

    unless ($sth = $self->{db}->prepare("DELETE FROM $self->{tbl} WHERE id=?")
	    and $sth->execute($id)) {
	carp "Could not remove user $id";
	return undef;
    }

    return 1;
}

######################################################################
# Private methods and functions

sub _get_field {
    my ($self, $id, $field, $sth);
    $self = shift;
    $id = shift;
    $field = shift;

    unless (_is_valid_field($field)) {
	carp "Invalid field: $field";
	return undef;
    }

    $sth=$self->{db}->prepare("SELECT $field FROM $self->{tbl} WHERE id = ?");
    $sth->execute($id);

    return $sth->fetchrow_array;
}

sub _set_field { 
    my ($self, $id, $field, $val, $sth);
    $self = shift;
    $id = shift;
    $field = shift;
    $val = shift;

    unless (_is_valid_field($field) or $field eq 'passwd') {
	carp "Invalid field: $field";
	return undef;
    }

    unless ($sth = $self->{db}->prepare("UPDATE $self->{tbl} SET $field = ? 
            WHERE id = ?") and $sth->execute($val, $id)) {
	carp "Could not set $field to $val for user $id";
	return undef;
    }

    return 1;
}

sub _is_valid_field {
    my $field = shift;
    return ($field =~ /^(login|name|level)$/) ? 1 : 0;
}

1;
