# vim: set ft=perl ts=4 sw=4:
# POE::Component::Client::Haver - obvious.
# 
# Copyright (C) 2004 Bryan Donlan, Dylan William Hardison.
# 
# This module is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This module is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this module; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


=head1 NAME

POE::Component::Client::Haver - POE Component for Haver clients.

=head1 SYNOPSIS

  use POE::Component::Client::Haver;

  new POE::Component::Client::Haver('haver');
  POE::Kernel->post('haver', 'connect', Host => 'example.com',
  					Port => 7070,
					UID  => 'example');

=head1 DESCRIPTION

POE::Component::Client::Haver is a POE component for writing Haver clients.
Generally one will create a session with new(), register for all events with
register(), and then send commands and receive events from the session.

=head1 METHODS

=cut

package POE::Component::Client::Haver;
use strict;
use warnings;

use POE qw(Wheel::ReadWrite
	   Wheel::SocketFactory);
use Haver::Preprocessor;
use Haver::Misc qw(format_datetime);
use POE::Filter::Haver;
use Haver::Formats::Error;
use Carp;
use Digest::SHA1 qw(sha1_base64);
require Exporter;

our $VERSION = 0.06;

sub _call {
	return POE::Kernel->call(POE::Kernel->get_active_session(), @_);
}

sub _dprint {
	my ($level, @text) = @_;
	return unless POE::Kernel->get_active_session()->get_heap()->{debug} >= $level;
	print STDERR @text;
}

sub _dprintf {
	my ($level, $fmt, @text) = @_;
	return unless POE::Kernel->get_active_session()->get_heap()->{debug} >= $level;
	printf STDERR $fmt, @text;
}


### SETUP

=head2 new($Z<>alias)

Creates a new POE::Component::Client::Haver session with alias $alias

=cut

sub new ($$) {
	my ($class, $alias) = @_;
	carp "Can't call ->new on a ".(ref $class)." instance" if ref $class;
	carp "Haver::Client can't be subclassed" if($class ne __PACKAGE__);
	POE::Session->create(package_states =>
			 [ __PACKAGE__,
			   [qw{
					_start
					setoptions

					register
					unregister
					dispatch

					connect
					connected
					connectfail

					input
					send_raw
					send
					net_error

					destroy
					disconnect
					force_close
					flushed
					cleanup
					_stop

					login
					join
					part
					msg
					pmsg
					users
					make
					chans

					event_WANT
					event_ACCEPT
					event_REJECT
					event_PING
					event_CLOSE
					event_IN
					
					event_JOIN
					event_PART
					event_MSG
					event_PMSG
					event_USERS
					event_BYE
					event_QUIT
					event_CHANS
					event_WARN
					event_DIE

					_default

				   }]],
			 args => [$alias]
			 );
	return 1;
}

sub _start {
	my ($kernel, $heap, $session, $alias, @args) = @_[KERNEL,HEAP,SESSION,ARG0];
	$kernel->alias_set($alias);
	%$heap = (alias => $alias,
		 	registrations => {},
			scope => undef,
			debug => 0,
			autorespond => { 'PING?' => 1, 'TIME?' => 1 },
			);
	if(@args) {
		_call('setoptions', @args);
	}
}

=head1 MESSAGES

=head2 setoptions(option => value [, ...])

Sets one or more options to the given value. The following options are available:

=head3 debug => level

Sets debugging to the given level. 0 will disable debugging.

=head3 autorespond => [ ... ]

Enables autoresponding to certain types of messages. Currently only PING? and TIME? are supported.

=cut

sub setoptions {
	my ($kernel, $heap, %args) = @_[KERNEL,HEAP,ARG0..$#_];
	my %setters = (
		debug => sub { $heap->{debug} = $_[0]; },
		autorespond => sub { $heap->{autorespond} = map { ($_ => 1) } @_ },
	);
	for (keys %args) {
		$setters{$_}->($args{$_}) if exists $setters{$_};
	}
}

### DISPATCH

=head2 register($Z<>event1 [,...])

Registers to receive the events listed. When a matching event is dispatched, it will be sent to
the calling session as 'haver_eventname'. The special event name 'all' may be specified to register for all
events. A given event will not be sent to any given session more than once.

=cut

sub register {
	my ($kernel, $heap, $sender, @events) = @_[KERNEL,HEAP,SENDER,ARG0..$#_];
	for(@events) {
		if(!exists $heap->{registrations}->{$_}->{$sender->ID}) {
			$heap->{registrations}->{$_}->{$sender->ID} = $heap->{alias} . "##$_";
			$kernel->refcount_increment($sender->ID, $heap->{alias} . "##$_");
		}
	}
}

=head2 unregister($Z<>event1 [,...])

Unregisters from the specified event. Events registered using 'all' must be unregistered using 'all'.

=cut

sub unregister {
	my ($kernel, $heap, $sender, @events) = @_[KERNEL,HEAP,SENDER,ARG0..$#_];
	for(@events) {
		if(exists $heap->{registrations}->{$_}->{$sender->ID}) {
			delete $heap->{registrations}->{$_}->{$sender->ID};
			$kernel->refcount_decrement($sender->ID, $heap->{alias} . "##$_");
		}
	}
}

sub dispatch {
	my ($kernel, $heap, $event, @args) = @_[KERNEL,HEAP,ARG0..$#_];
	my %targets = (map { $_ => 1 } (keys(%{$heap->{registrations}->{$event}}),
					keys(%{$heap->{registrations}->{all}})));
	$kernel->post($_, "haver_$event", [@args], $heap->{scope}) for keys %targets;
}

### SESSION MANAGEMENT

=head2 B<connect(Host => $Z<>host, [Port => $Z<>port, UID => $Z<>uid, Password => $Z<>password])

Connects to the haver server. The Host option is mandatory, all others are optional.
If it is already connected, it will disconnect, then connect with the new parameters

=cut

sub connect {
	my ($kernel, $heap, %args) = @_[KERNEL,HEAP,ARG0..$#_];
# XXX: Better error reporting
	croak "Missing required parameter Host" unless exists $args{Host};
	if(exists $heap->{conn}) {
		$kernel->yield('disconnect') unless exists $heap->{pending_connection};
		$heap->{pending_connection} = [%args];
		return;
	}
	$heap->{UID} = $args{UID};
	$heap->{PASS} = $args{Password};
	$args{Port} ||= 7070;
	$heap->{connect_wheel} =
	POE::Wheel::SocketFactory->new(
						RemoteAddress => $args{Host},
						RemotePort => $args{Port},
						SuccessEvent => 'connected',
						FailureEvent => 'connectfail'
						);
}

=head2 disconnect(Z<>)

Disconnects from the Haver server. If not already connected, does nothing. This event
may not complete immediately.

=cut

sub disconnect {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	return if $heap->{closing};
	$heap->{closing} = 1;
	if($heap->{want}) {
		$kernel->yield('cleanup');
	}else{
		$kernel->yield('send', 'QUIT');
		$kernel->delay('force_close', 5);
	}
}

sub connected {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	my ($handle, $id) = @_[ARG0,ARG3];
	if(!exists $heap->{connect_wheel} ||
		$heap->{connect_wheel}->ID() != $id){
		close $handle;
		return;
	}
	binmode $handle, ':utf8';
	$heap->{conn} =
	POE::Wheel::ReadWrite->new(
				   Handle => $handle,
				   Driver => POE::Driver::SysRW->new(),
				   Filter => POE::Filter::Haver->new(),
				   InputEvent => 'input',
				   FlushedEvent => 'flushed',
				   ErrorEvent => 'net_error'
				   );
	delete $heap->{connect_wheel};
	$heap->{flushed} = 1;
	_call('dispatch', 'connected');
}

sub connectfail {
	my ($kernel, $heap, $enum, $estr) = @_[KERNEL,HEAP,ARG1,ARG2];
	_call('dispatch', 'connect_fail', $enum, $estr);
	delete $heap->{connect_wheel};
}

sub net_error {
	my ($kernel, $heap, $enum, $estr) = @_[KERNEL,HEAP,ARG1,ARG2];
	_call('dispatch', 'disconnected', $enum, $estr);
	$kernel->yield('cleanup');
}

### IO

sub input {
	my ($kernel, $heap, $event) = @_[KERNEL,HEAP,ARG0];
	_dprint 1, "S: ", join("\t", @$event), "\n" unless defined $heap->{scope};
	my $ename = shift @$event;
	_call('dispatch', 'raw_in', $ename, @$event) unless defined $heap->{scope};
	_call("event_$ename", @$event);
}

=head2 send_raw(@args)

Sends the arguments specified to the haver server. No checking is performed, though escaping may occur.

=cut

sub send_raw {
	my ($kernel, $heap, @message) = @_[KERNEL,HEAP,ARG0..$#_];
	return if ($heap->{want} && $heap->{want} eq "!impossible");
	eval { $heap->{conn}->put(\@message); };
	if($@) {
		# Ack, lost connection unexpectedly!
		# Hopefully we get net_error soon
		$heap->{want} = "!impossible";
		return;
	}
	_dprint 1, "C: ", join("\t", map { defined($_) ? $_ : '~UNDEF~' } @message), "\n";
	_call('dispatch', 'raw_out', @message);
}

sub send {
	my ($kernel, $heap, @message) = @_[KERNEL,HEAP,ARG0..$#_];
	if($heap->{want}) {
		if(($heap->{want} ne uc $message[0]) &&
		   ((uc $message[0] ne 'CANT') || ($message[1] ne $heap->{want}))) {
			_dprint 1, "(blocked) C: ", join("\t", @message), "\n";
			push @{$heap->{messageq} ||= []}, [@message];
			return;
		}
		delete $heap->{want};
	}
	$kernel->yield('send_raw', @message);
	if(exists $heap->{messageq}) {
		for (@{$heap->{messageq}}) {
			$kernel->yield('send', @$_);
		}
		delete $heap->{messageq};
	}
	$heap->{flushed} = 0;
}

### SERVER EVENTS

# XXX: Make a more extensible WANT system later
sub event_WANT {
	my ($kernel, $heap, $wanted, @arg) = @_[KERNEL,HEAP,ARG0,ARG1];
	$wanted = uc $wanted;
	$heap->{want} = $wanted;
	my %wants =
	(
	 VERSION => sub {
		 $kernel->yield('send', 'VERSION', "Haver::Client/$VERSION");
	 },
	 UID => sub {
		 if(defined $heap->{UID}) {
			 $kernel->yield('send', 'UID', $heap->{UID});
		 }else{
			 _call('dispatch', 'login_request');
		 }
	 },
	 PASS => sub {
		 if(defined $heap->{PASS}) {
			 $kernel->yield('send', 'PASS',
					sha1_base64(sha1_base64($heap->{PASS}) .
							$arg[0]));
		 }else{
			 _call('dispatch', 'login_request');
		 }
	 },
	 MODE => sub {
		 $kernel->yield('send', 'MODE', 'multi');
	 },
	 );
	if(exists $wants{$wanted}) {
		$wants{$wanted}();
	}else{
		$kernel->yield('send', 'CANT', $wanted);
	}
}

sub event_ACCEPT {
	my ($kernel, $heap) = @_[KERNEL,HEAP];
	$heap->{logged_in} = 1;
	_call('dispatch', 'login');
}

sub event_REJECT {
	my ($kernel, $heap, $uid, $err) = @_[KERNEL,HEAP,ARG0,ARG1];
	my $e = new Haver::Formats::Error;
	_call('dispatch', 'login_fail',
		   $err,
		   $e->get_short_desc($err),
		   $e->format( $e->get_long_desc($err), $uid )
		   );
	delete $heap->{UID};
	delete $heap->{PASS};
	$heap->{want} = 'UID';
}

sub event_PING {
	my ($kernel, $heap, @junk) = @_[KERNEL,HEAP,ARG0..$#_];
	$kernel->yield('send', 'PONG', @junk);
}

sub event_CLOSE {
	my ($kernel, $heap, $etyp, $estr) = @_[KERNEL,HEAP,ARG0,ARG1];
	_call('dispatch', 'close', $etyp, $estr);
}

sub event_JOIN {
	my ($kernel, $heap, $uid) = @_[KERNEL,HEAP,ARG0,ARG1];
	_call('dispatch', ($uid eq '.' ||
				$uid eq $heap->{UID}) ? 'joined' : 'join',
		   $uid);
}

sub event_PART {
	my ($kernel, $heap, $uid) = @_[KERNEL,HEAP,ARG0,ARG1];
	_call('dispatch', ($uid eq '.' ||
				$uid eq $heap->{UID}) ? 'parted' : 'part',
		   $uid);
}

my %autorespond = (
	'PING?' => sub {
		my ($kernel, $heap, $who, @junk) = @_[KERNEL,HEAP,ARG0..$#_];
		if(!@junk) {
			@junk = (''); # This silences a warning elsewhere
		}
		$kernel->yield('pmsg', 'PING', $who, @junk);
	},
	'TIME?' => sub {
		my ($kernel, $heap, $who) = @_[KERNEL,HEAP,ARG0];
		$kernel->yield('pmsg', 'TIME', $who, format_datetime(time()));
	},
);

sub event_MSG {
	my ($kernel, $heap, $uid, $type, @text) = @_[KERNEL,HEAP,ARG0..$#_];
	if ($heap->{autorespond}->{$type} && exists $autorespond{$type}) {
		$autorespond{$type}->(@_[0..ARG0-1], $uid, @text);
	}
	_call('dispatch', 'msg', $type, $uid, @text);
}

sub event_PMSG {
	my ($kernel, $heap, $uid, $type, @text) = @_[KERNEL,HEAP,ARG0..$#_];
	if ($heap->{autorespond}->{$type} && exists $autorespond{$type}) {
		$autorespond{$type}->(@_[0..ARG0-1], $uid, @text);
	}
	_call('dispatch', 'pmsg', $type, $uid, @text);
}

sub event_USERS {
	my ($kernel, $heap, @who) = @_[KERNEL,HEAP,ARG0..$#_];
	_call('dispatch', 'users', @who);
}

sub event_BYE {
	my ($kernel, $heap, $why) = @_[KERNEL,HEAP,ARG0];
	_call('dispatch', 'bye', $why);
}

sub event_QUIT {
	my ($kernel, $heap, $who, $why) = @_[KERNEL,HEAP,ARG0,ARG1];
	_call('dispatch', 'quit', $who, $why);
}

sub event_CHANS {
	my ($kernel, $heap, @channels) = @_[KERNEL,HEAP,ARG0..$#_];
	_call('dispatch', 'chans', @channels);
}

sub event_WARN {
	my ($kernel, $err, @args) = @_[KERNEL,ARG0..$#_];
	my $e = new Haver::Formats::Error;
	_call('dispatch', 'warn',
		   $err,
		   $e->get_short_desc($err),
		   $e->format( $e->get_long_desc($err), @args )
		   );
}

sub event_DIE {
	my ($kernel, $err, @args) = @_[KERNEL,ARG0..$#_];
	my $e = new Haver::Formats::Error;
	_call('dispatch', 'die',
		   $err,
		   $e->get_short_desc($err),
		   $e->format( $e->get_long_desc($err), @args )
		   );
}

sub event_IN {
	my ($kernel, $heap, $scope, @cmd) = @_[KERNEL,HEAP,ARG0..$#_];
	my $save = $heap->{scope};
	$heap->{scope} = $scope;
	_call('input', \@cmd);
	$heap->{scope} = $save;
}

### CLIENT EVENTS

=head2 login($Z<>uid [, $Z<>pass])

Specify a UID and password to use for the next login. If already logged in, this takes effect on the next connection
unless overridden by connect(). If the server is waiting for a login, takes effect immediately.

=cut

sub login {
	my ($kernel, $heap, $uid, $pass) = @_[KERNEL,HEAP,ARG0,ARG1];
	$heap->{UID} = $uid;
	$heap->{PASS} = $pass;
	if($heap->{want}) {
	if($heap->{want} eq 'UID') {
		if(!defined $uid) {
			# oops...
			delete $heap->{UID};
			delete $heap->{PASS};
			_call('dispatch', 'login_fail', 'UNDEF_UID', 'Undefined UID',
					   'Internal client error: UID is undefined');
			return;
		}
		$kernel->yield('send', 'UID', $heap->{UID});
	} elsif($heap->{want} eq 'PASS') {
		if(defined $pass) {
			$kernel->yield('send', 'PASS', $pass);
		}else{
			$kernel->yield('send', 'CANT', 'PASS');
		}
	}
	}
}

=head2 join($Z<>channel)

Attempts to join $channel

=cut

sub join {
	my ($kernel, $heap, $where) = @_[KERNEL,HEAP,ARG0];
	$kernel->yield('send', 'JOIN', $where);
}

=head2 part($Z<>channel)

Parts $Z<>channel

=cut

sub part {
	my ($kernel, $heap, $where) = @_[KERNEL,HEAP,ARG0];
	$kernel->yield('send', 'PART', $where);
}

=head2 make($Z<>channel)

Ask the server to create a channel $channel.

=cut

sub make {
	my ($kernel, $heap, $cid) = @_[KERNEL,HEAP,ARG0];
	$kernel->yield('send', 'MAKE', $cid);
}

=head2 B<msg($Z<>type, $Z<>channel, $Z<>text)>

Sends a message with specified type and text to $channel.

=cut

sub msg {
	my ($kernel, $heap, $type, $where, $message) = @_[KERNEL,HEAP,ARG0..ARG2];
	$kernel->yield('send', 'IN', $where, 'MSG', $type, $message);
}

=head2 B<pmsg($Z<>type, $Z<>uid, $Z<>text)>

Sends a private message with specified type and text to $uid.

=cut

sub pmsg {
	my ($kernel, $heap, $type, $where, $message) = @_[KERNEL,HEAP,ARG0..ARG2];
	$kernel->yield('send', 'PMSG', $where, $type, $message);
}

=head2 users($Z<>channel)

Ask the server which users are on $channel.

=cut

sub users {
	my ($kernel, $heap, $where) = @_[KERNEL,HEAP,ARG0];
	$kernel->yield('send', 'IN', $where, 'USERS');
}

=head2 chans(Z<>)

Ask the server for a list of all channels

=cut

sub chans {
	my $kernel = $_[KERNEL];
	$kernel->yield('send', 'CHANS');
}

### SHUTDOWN

sub force_close {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	return if $heap->{closing} == 3;
	if($heap->{closing} == 2 || $heap->{flushed}){ # Flushed or flush timeout
		$kernel->yield('cleanup');
		_call('dispatch', 'disconnected', -1, 'Disconnected');
		$kernel->delay('force_close');
		$heap->{closing} = 3;
		return;
	}
	$heap->{closing} = 2;
	$kernel->delay('force_close', 5);
}

sub flushed {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	if(defined $heap->{closing} && $heap->{closing} == 2) {
		$kernel->yield('force_close');
	}
	$heap->{flushed} = 1;
}

sub cleanup {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	delete $heap->{$_} for qw(conn flushed closing UID PASS want messageq);
	$kernel->delay('force_close');
	if($heap->{destroy_pending}) {
		$kernel->yield('destroy');
	}elsif(exists $heap->{pending_connection}) {
		$kernel->yield('connect', @{$heap->{pending_connection}});
		delete $heap->{pending_connection};
	}
}

=head2 destroy(Z<>)

Disconnects from the Haver server, and destroys the session. This event may not complete
immediately, so you should not attempt to create another session with the same alias
until it finishes.

=cut

sub destroy {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	_dprint 1, "Destroying.\n";
	if(exists $heap->{conn}){
		$heap->{destroy_pending} = 1;
		$kernel->yield('disconnect');
	return;
	}
	$kernel->alias_remove($heap->{alias});
}

sub _stop {
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	foreach my $evt (keys %{$heap->{registrations}}) {
		my $ehash = $heap->{registrations}->{$evt};
		foreach my $session (keys %$ehash) {
			my $refcount = $ehash->{$session};
			$kernel->refcount_decrement($session, $refcount);
		}
	}
}

sub _default {
	my ( $kernel, $state, $event, $args, $heap ) = @_[ KERNEL, STATE, ARG0, ARG1, HEAP ];
	$args ||= [];	# Prevents uninitialized-value warnings.
	DEBUG: "default: $state = $event. Args:\n";
	DUMP: $args;
	return 0;
}


1;
__END__

=head1 EVENTS

Event callbacks are called with the frist argument being the event arguments and
the second argument being the scope set by IN (or undef if not set). Example:

  sub haver_connect_fail {
  	my ($args, $scope) = @_[ARG0,ARG1];
	my ($enum, $estr) = @$args;
	# ...
  }

=head2 haver_connected(Z<>)

This event is sent when a connection is established (but before it is logged in)

=head2 haver_connect_fail($Z<>enum, $Z<>estr)

The connection could not be established. An error code is in $enum, and the human-readable
version is in $estr

=head2 haver_disconnected($Z<>enum, $Z<>estr)

The connection has been lost. If the server closed the connection, $enum will be 0 and $estr will
be meaningless. If the user closed the connection, and the server failed to respond, $enum will be -1.
Otherwise, $enum will contain an error code, and $estr the human-readable version.

=head2 haver_raw_in(@data)

The client has received @data from the Haver server. Mostly useful for debugging.

=head2 haver_raw_out(@data)

The client has sent @data to the Haver server. Mostly useful for debugging.

=head2 haver_login_request(Z<>)

The server is asking for a login, and one was not provided in connect(). The connection will not proceed until
login() is sent with the UID and (optionally) password.

=head2 haver_login(Z<>)

The client has successfully logged in.

=head2 haver_login_fail($Z<>error, $Z<>error_short, $Z<>error_long, $Z<>uid)

Login with UID $uid has failed with error $error. Human-readable short and long versions, respectively, are
in $error_short and $error_long.

=head2 haver_close($Z<>etyp, $Z<>estr)
Z<XXX: Describe args>

Server is closing connection, and sent $etyp and $estr

=head2 haver_join($Z<>cid, $Z<>uid)

$uid has joined channel $cid.

=head2 haver_joined($Z<>cid)

The client has joined channel $cid.

=head2 haver_part($Z<>cid, $Z<>uid)

$uid has left $cid.

=head2 haver_parted($Z<>cid)

The client has left $Z<>cid.

=head2 haver_msg($Z<>type, $Z<>cid, $Z<>uid, $Z<>text)

A public message with type $type and contents $text was sent on channel $cid by user $uid.

=head2 haver_pmsg($Z<>type, $z<>uid, $Z<>text)

A private message with type $type and contents $text was sent to you by user $uid.

=head2 haver_users($Z<>where, @Z<>who)

Channel $where has the users listed in @who in it. Sent in response to message users().

=head2 haver_bye($Z<>why)

The server is disconnecting you due to the reason in $why

=head2 haver_chans(@Z<>channels)

The server has the channels listed in @channels. Sent in response to message chans()

=head2 haver_warn($Z<>err, $Z<>short, $Z<>long, @Z<>args)

The server has sent a non-fatal error message with code $err and arguments @args. $short and $long have the
short and long human-readable forms, respectively.

=head2 haver_die($Z<>err, $Z<>short, $Z<>long, @Z<>args)

The server has sent a non-fatal error message with code $err and arguments @args. $short and $long have the
short and long human-readable forms, respectively. The connection will be closed shortly.

=head1 SEE ALSO

L<http://wiki.chani3.com/wiki/ProjectHaver/>

=head1 AUTHOR

Bryan Donlan, E<lt>bdonlan@bd-home-comp.no-ip.orgE<gt> and
Dylan William Hardison, E<lt>dylanwh@tampabay.rr.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Bryan Donlan, Dylan William Hardison

This library is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this module; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


=cut
