package Net::SSH2::Channel;

use strict;
use warnings;
use Carp;

# methods

sub shell {
    $_[0]->process('shell')
}

sub exec {
    $_[0]->process(exec => $_[1])
}

sub subsystem {
    $_[0]->process(subsystem => $_[1])
}

sub error {
    shift->session->error(@_)
}

sub setenv {
    my ($self, %env) = @_;
    my $rc = 1;
    while (my ($k, $v) = each %env) {
        $self->_setenv($k, $v)
            or undef $rc;
    }
    $rc
}


# tie interface

sub PRINT {
    my $self = shift;
    my $sep = defined($,) ? $, : '';
    $self->write(join $sep, @_)
}

sub PRINTF {
    my $self = shift;
    $self->write(sprintf @_)
}

sub WRITE {
    my ($self, $buf, $len, $offset) = @_;
    $self->write(substr($buf, $offset, $len))
}

sub READLINE {
    my $self = shift;
    return if $self->eof;

    if (wantarray) {
        my @lines;
        my $line;
        push @lines, $line while defined($line = $self->READLINE);
        return @lines;
    }
    
    my ($line, $eol, $c) = ('', $/);
    $line .= $c while $line !~ /\Q$eol\E$/ and defined($c = $self->GETC);
    length($line) ? $line : undef
}

sub GETC {
    my $self = shift;
    my $buf;
    my @poll = ({ handle => $self, events => 'in' });
    return
     unless $self->session->poll(250, \@poll) and $poll[0]->{revents}->{in};
    $self->read($buf, 1) ? $buf : undef
}

sub READ {
    my ($self, $rbuf, $len, $offset) = @_;
    my ($tmp, $count);
    return unless defined($count = $self->read($tmp, $len));
    substr($$rbuf, $offset) = $tmp;
    $count
}

sub CLOSE {
    &close
}

sub BINMODE {
}

sub EOF {
    &eof
}

1;
__END__

=head1 NAME

Net::SSH2::Channel - SSH2 channel object

=head1 SYNOPSIS

  my $chan = $ssh2->channel()
    or $ssh2->die_with_error;

  $chan->exec("ls -ld /usr/local/libssh2*")
    or $ssh2->die_with_error;

  $chan->send_eof;

  while (<$chan>) {
    print "line read: $_";
  }

  print "exit status: " . $chan->exit_status . "\n";

=head1 DESCRIPTION

A channel object is created by the L<Net::SSH2> C<channel> method.  As well
as being an object, it is also a tied filehandle.  The L<Net::SSH2> C<poll>
method can be used to check for read/write availability and other conditions.

=head2 setenv ( key, value ... )

Sets remote environment variables.  Note that most implementations do not allow
environment variables to be freely set.  Pass in a list of keys and values
with the values to set.

It returns a true value when all the given environment variables are
correctly set.

=head2 blocking ( flag )

Enable or disable blocking.  Note that this is currently implemented in libssh2
by setting a per-session flag; it's equivalent to L<Net::SSH2::blocking>.

=head2 eof

Returns true if the remote server sent an EOF.

=head2 send_eof

Send an EOF to the remote.

After an EOF has been sent, no more data may be
sent to the remote process C<stdin> channel.

=head2 close

Close the channel (happens automatically on object destruction).

=head2 wait_closed

Wait for a remote close event.  Must have already seen remote EOF.

=head2 exit_status

Returns the channel's program exit status.

=head2 pty ( terminal [, modes [, width [, height ]]] )

Request a terminal on a channel.  If provided, C<width> and C<height> are the
width and height in characters (defaults to 80x24); if negative their absolute
values specify width and height in pixels.

=head2 pty_size ( width, height )

Request a terminal size change on a channel. C<width> and C<height> are the
width and height in characters; if negative their absolute values specify
width and height in pixels.

=head2 ext_data ( mode )

Set extended data handling mode:

=over 4

=item normal (default)

Keep data in separate channels; stderr is read separately.

=item ignore

Ignore all extended data.

=item merge

Merge into the regular channel.

=back

=head2 process ( request, message )

Start a process on the channel.  See also L<shell>, L<exec>, L<subsystem>.

Note that only one invocation of C<process> or any of the shortcuts
C<shell>, C<exec> or C<subsystem> is allowed per channel. In order to
run several commands, shells or/and subsystems, a new C<Channel>
instance must be used for every one.

Alternatively, it is also possible to launch a remote shell (using
L<shell>) and simulate the user interaction printing commands to its
C<stdin> stream and reading data back from its C<stdout> and
C<stderr>. But this approach should be avoided if possible; talking to
a shell is difficult and, in general, unreliable.

=head2 shell

Start a shell on the remote host (calls C<process("shell")>).

=head2 exec ( command )

Execute the command on the remote host (calls C<process("exec", command)>).

Note that the given command is parsed by the remote shell; it should
be properly quoted, specially when passing data from untrusted sources.

=head2 subsystem ( name )

Run subsystem on the remote host (calls C<process("subsystem", name)>).

=head2 read ( buffer, size [, ext ] )

Attempts to read size bytes into the buffer.  Returns number of bytes read,
undef on failure.  If ext is present and set, reads from the extended data
channel (stderr).

=head2 write ( buffer [, ext ] )

Attempts to write the buffer to the channel.  Returns number of bytes written,
undef on failure.  If ext is present and set, writes to the extended data
channel (stderr).

In versions of this module prior to 0.57, when working in non-blocking
mode, the would-block condition was signaled by returning
LIBSSH2_ERROR_EAGAIN (a negative number) while leaving the session
error status unset. From version 0.59, C<undef> is returned and the
session error status is set to C<LIBSSH2_ERROR_EAGAIN> as for any
other error.

In non-blocking mode, if C<write> fails with a C<LIBSSH2_ERROR_EAGAIN>
error. No other operation must be invoked over any object in the same
SSH session besides L</sock> and L<blocking_directions>.

Once the socket becomes ready again, the exact same former C</write>
call, with exactly the same arguments must be invoked.

Failing to do that would result in a corrupted SSH session. This is a
limitation in libssh2.

=head2 flush ( [ ext ] )

Flushes the channel; if C<ext> is present and set, flushes extended
data channel. Returns number of bytes flushed, C<undef> on error.

=head2 exit_signal

Returns the exit signal of the command executed on the channel.

=head2 window_read

Returns the number of bytes which the remote end may send without
overflowing the window limit.

In list context it also returns the number of bytes that are
immediately available for read and the size of the initial window.

=head2 window_write

Returns the number of bytes which may be safely written to the channel
without blocking at the SSH level. In list context it also returns the
size of the initial window.

Note that this method doesn't take into account the TCP connection
being used under the hood. Getting a positive integer back from this
method does not guarantee that such number of bytes could be written
to the channel without blocking the TCP connection.

=head2 receive_window_adjust (adjustment [, force])

Adjust the channel receive window by the given C<adjustment> bytes.

If the amount to be adjusted is less than C<LIBSSH2_CHANNEL_MINADJUST>
and force is false the adjustment amount will be queued for a later
packet.

On success returns the new size of the receive window. On failure it
returns C<undef>.

=head1 SEE ALSO

L<Net::SSH2>.

=cut
