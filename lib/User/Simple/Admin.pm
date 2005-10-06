# $Id: Admin.pm,v 1.7 2005/06/15 17:17:10 gwolf Exp $
use warnings;
use strict;

package User::Simple::Admin;

=head1 NAME

User::Simple::Admin - User::Simple user administration

=head1 SYNOPSIS

  $ua = User::Simple::Admin->new($db, $user_table);

  $ua = User::Simple::Admin->create_db_structure($db, $user_table);
  $ok = User::Simple::Admin->has_db_structure($db, $user_table);

  %users = $ua->dump_users;

  $id = $ua->id($login);
  $login = $ua->login($id);
  $name = $ua->name($id);
  $is_admin = $ua->is_admin($id);

  $ok = $usr->set_login($id, $login);
  $ok = $usr->set_name($id, $name);
  $ok = $usr->set_admin($id);
  $ok = $usr->unset_admin($id);
  $ok = $usr->set_passwd($id, $passwd);
  $ok = $usr->clear_session($id);

  $id = $ua->new_user($login, $name, $passwd, $is_admin);

  $ok = $ua->remove_user($id);

=head1 DESCRIPTION

Administrative actions for User::Simple modules are handled through this
Admin object. To instantiate it:

  $a = User::Simple::Admin->new($db, $user_table);

$db is an open connection to the database where the user data is stored. 

If we do not yet have the needed DB structure to store the user information,
we can use this method as a constructor as well. 

  $ok = User::Simple::Admin->create_db_structure($db, $user_table)

In order to check if the database is ready to be used by this module with the
specified table name. 

  %users = $ua->dump_users;

Will return a hash with the data regarding the registered users, in the 
following form:

  ( $id1 => { is_admin => $is_admin1, name => $name1, login => $login1},
    $id2 => { is_admin => $is_admin2, name => $name2, login => $login2},
    (...) )

  $id = $ua->new_user($login, $name, $passwd, $is_admin);

Creates a new user with the specified data. $is_admin is a boolean value - Use
1 for true, 0 for false. Returns the new user's ID.

  $ok = $ua->remove_user($id);

Removes the user specified by the ID.

  $id = $ua->id($login);
  $login = $ua->login($id);
  $name = $ua->name($id);
  $is_admin = $ua->is_admin($id);

Get the value of each of the mentioned attributes. Note that in order to get
the ID you can supply the login, every other method answers only to the ID. In
case you have the login and want to get the name, you should use 
C<$ua->name($ua->id($login));>

  $ok = $usr->set_login($id, $login);
  $ok = $usr->set_name($id, $name);
  $ok = $usr->set_passwd($id, $passwd);

Modifies the requested attribute of the specified user, setting it to the new 
value.

  $ok = $usr->set_admin($id);
  $ok = $usr->unset_admin($id);

Sets or removes the administrative status of this user.

  $ok = $usr->clear_session($id);

Removes the session which the current user had open, if any.

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
    my ($self, $class, $db, $table);
    $class = shift;
    $db = shift;
    $table = shift;

    # Verify we got the right arguments
    unless (isa($db, 'DBI::db')) {
	carp "First argument must be a DBI connection";
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

    $self = { db => $db, tbl => $table };

    bless $self, $class;
    return $self;
}

######################################################################
# Creating the needed structure

sub create_db_structure {
    my ($class, $db, $table, $sth);
    $class = shift;
    $db = shift;
    $table = shift;

    # Remember some DBD backends don't implement 'serial' - Use 'integer' and
    # some logic on our side instead
    unless ($sth = $db->prepare("CREATE TABLE $table (
            id integer PRIMARY KEY, 
            login varchar NOT NULL UNIQUE,
            name varchar NOT NULL,
            passwd varchar,
            is_admin bool NOT NULL DEFAULT 'f',
            session varchar UNIQUE,
            session_exp varchar)") and $sth->execute) {
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
    return 1 if ($sth=$db->prepare("SELECT id, login, name, passwd, is_admin, 
                 session, session_exp FROM $table LIMIT 1") and $sth->execute);
    return 0;
}

######################################################################
# Retrieving information

sub dump_users { 
    my ($self, $order, $sth, %users);
    $self = shift;

    unless ($sth = $self->{db}->prepare("SELECT id, login, name, is_admin
            FROM $self->{tbl}") and $sth->execute) {
	carp 'Could not query for the user list';
	return undef;
    }

    while (my @row = $sth->fetchrow_array) {
	$users{$row[0]} = {login => $row[1],
			   name => $row[2],
			   is_admin => $row[3]
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

sub is_admin {
    my ($self, $id);
    $self = shift;
    $id = shift;
    return $self->_get_field($id, 'is_admin'); 
}

######################################################################
# Modifying information

sub set_login { 
    my ($self, $id, $new);
    $self = shift;
    $id = shift;
    $new = shift;
    return $self->_set_field($id, 'login', $new);
}

sub set_name { 
    my ($self, $id, $new);
    $self = shift;
    $id = shift;
    $new = shift;
    return $self->_set_field($id, 'name', $new);
}

sub set_admin { 
    my ($self, $id);
    $self = shift;
    $id = shift;
    return $self->_set_field($id, 'is_admin', 1);
}

sub unset_admin { 
    my ($self, $id);
    $self = shift;
    $id = shift;
    return $self->_set_field($id, 'is_admin', 0);
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
    my ($self, $login, $name, $passwd, $is_adm, $id, $orig_re);
    $self = shift;
    $login = shift;
    $name = shift;
    $passwd = shift;
    $is_adm = shift || 0; # Don't whine on undef

    $orig_re = $self->{db}->{RaiseError};
    eval {
	my ($sth, $id);
	$self->{db}->begin_work;
	$self->{db}->{RaiseError} = 1;

	# Not all DBD backends implement the 'serial' datatype - We use a
	# simple integer, and we just move the 'serial' logic to this point,
	# the only new user creation area. 
	# Yes, this could lead to a race condition and to the attempt to insert
	# two users with the same ID - We have, however, the column as a 
	# 'primary key'. Any DBD implementing unicity will correctly fail. 
	# And... Well, nobody expects too high trust from DBD::CSV, right? :)
	$sth = $self->{db}->prepare("SELECT id FROM $self->{tbl} ORDER BY
            id desc LIMIT 1");
	$sth->execute;
	($id) = $sth->fetchrow_array;
	$id++;

	$sth = $self->{db}->prepare("INSERT INTO $self->{tbl} (id, login, name,
            is_admin) VALUES (?, ?, ?, ?)");
	$sth->execute($id, $login, $name, $is_adm?1:0);

	$id = $self->id($login);
	$self->set_passwd($id, $passwd);

	$self->{db}->commit;
	$self->{db}->{RaiseError} = $orig_re;
    };
    if ($@) {
	$self->{db}->rollback;
	$self->{db}->{RaiseError} = $orig_re;
	carp "Could not create specified user";
	return undef;
    }
    return 1;
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
    return ($field =~ /^(login|name|is_admin)$/) ? 1 : 0;
}

1;

# $Log: Admin.pm,v $
# Revision 1.7  2005/06/15 17:17:10  gwolf
# Some documentation fixes
# User::Simple: Finishing touches to breathe independent life to it, so it will
# become a project of its own ;-)
#
# Revision 1.6  2005/05/10 05:06:24  gwolf
# Replace Crypt::PasswdMD5 for Digest::MD5 for consistency
#
# Revision 1.5  2005/05/02 19:11:55  gwolf
# Fixed a simple warning
#
# Revision 1.4  2005/04/06 23:00:09  gwolf
# Documented
#
# Revision 1.3  2005/04/05 00:33:39  gwolf
# - Admin: Fixed create_db_structure to reflect documented behavior
# - Documentation details added
#
