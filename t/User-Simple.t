# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl User-Simple.t'

use strict;
use DBI;
use File::Temp qw(tempdir);
use lib qw(/home/gwolf/User-Simple/lib);
my ($db, $dbdir);

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 33;
BEGIN { use_ok('User::Simple'); use_ok('User::Simple::Admin') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

$dbdir = tempdir (CLEANUP => 1); # CLEANUP removes directory upon exiting
eval { $db = DBI->connect("DBI:XBase:$dbdir") };

SKIP: {
    my ($ua, $adm_id, $usr_id, $usr, $session, %users);
    skip 'Not executing the complete tests: Database handler not created ' .
	'(I need DBD::XBase for this)', 14 unless $db;

    ###
    ### First, the User::Simple::Admin tests...
    ###

    # Create now the database and our table - Add 'name' and 'level' field, so
    # we remain compatible with previous User::Simple incarnations
    ok($ua = User::Simple::Admin->create_plain_db_structure($db,'user_simple',
				 'name varchar(30), level integer'),
       'Created a new table and an instance of a User::Simple::Admin object');

    # Create some user accounts
    ok(($ua->new_user(login => 'admin',
		      name => 'Administrative user',
		      passwd => 'Iamroot',
		      level => 5) and
	$ua->new_user(login => 'adm2',
		      name => 'Another administrative user',
		      passwd => 'stillagod',
		      level => 2) and
	$ua->new_user(login => 'user1',
		      name => 'Regular user 1',
		      passwd => 'a_password',
		      level => 0) and
	$ua->new_user(login => 'user2',
		      name => 'Regular user 2',
		      passwd => 'a_password',
		      level => 0) and
	$ua->new_user(login => 'user3',
		      name => 'Regular user 3',
		      passwd => 'a_password',
		      level => 0) and
	$ua->new_user(login => 'user4',
		      name => 'Regular user 4',
		      passwd => '',
		      level => 0) and
	$ua->new_user(login => 'user5',
		      name => 'Regular user 5',
		      passwd => 'a_password',
		      level => 0)),
       'Created some users to test on');

    # Does dump_users report the right amount of users?
    %users = $ua->dump_users;
    is(scalar(keys %users), 7, 'Right number of users reported');

    # Now do some queries on them...
    $adm_id = $ua->id('admin');
    $usr_id = $ua->id('user2');

    # Get the information they were created with
    is($ua->login($adm_id), 'admin', 'First user reports the right login');
    is($ua->name($adm_id), 'Administrative user', 
       'First user reports the right name');
    is($ua->level($adm_id), 5, 'First user reports the right level');
    
    is($ua->login($usr_id), 'user2', 'Second user reports the right login');
    is($ua->name($usr_id), 'Regular user 2', 
       'Second user reports the right name');
    is($ua->level($usr_id), 0, 'Second user reports the right level');

    # Change their details
    ok($ua->set_login($usr_id, 'luser1'), 
       'Successfully changed the user login');
    is($ua->id('luser1'), $usr_id, 'Changed user login reported correctly');

    ok(($ua->set_name($usr_id, 'Irregular luser 1') and 
	$ua->set_level($usr_id, 1)),
       "Successfully changed other of this user's details");

    diag('Next test will issue a warning - Disregard.');
    ok(!($ua->set_login($adm_id, 'adm2')),
       'System successfully prevents me from having duplicate logins');

    # Remove a user, should be gone.
    ok($ua->remove_user($usr_id), 'Removed a user');
    ok(!($ua->id('luser1')), 'Could not query for the removed user - Good.');

    ###
    ### Now, the User::Simple tests
    ###
    ok($usr = User::Simple->new(db=>$db, tbl=>'user_simple'),
       'Created a new instance of a User::Simple object');

    # Log in with user/password as user4 - As the password is blank, it should
    # be marked as disabled
    ok(!($usr->ck_login('user4','')),
       'Blank password is successfully disabled');

    # Log in with user/password, retrieve the user's data
    ok($usr->ck_login('user5','a_password'),
       'Successfully logged in with one of the users');
    is($usr->login, 'user5', 'Reported login matches');
    is($usr->name, 'Regular user 5', 'Reported name matches');
    is($usr->level, 0, 'Reported level matches');

    # Get the user's session
    ok($session = $usr->session, "Retreived the user's session");

    # Try to log in with an invalid session, check that all of the data is
    # cleared.
    is($usr->ck_session('blah'), undef,
       'Checked for a wrong session, successfully got refused');
    is($usr->id, undef, "Nobody's ID successfully reports nothing");
    is($usr->login, undef, "Nobody's login successfully reports nothing");
    is($usr->name, undef, "Nobody's name successfully reports nothing");
    is($usr->level, undef, "Nobody's level successfully reports nothing");

    # Now log in using the session we just retreived - We should get the 
    # full data again.
    ok($usr->ck_session($session), 'Successfully checked for a real session');
    is($usr->login, 'user5', 'Reported login matches');
    is($usr->name, 'Regular user 5', 'Reported name matches');
    is($usr->level, 0, 'Reported level matches');

}
