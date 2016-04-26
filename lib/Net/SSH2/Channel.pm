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

sub read1 {
    my $self = shift;
    my $buffer;
    my $rc = $self->read($buffer, @_);
    return (defined $rc ? $buffer : undef);
}

sub read2 {
    my ($self, $max_size) = @_;
    $max_size = 32678 unless defined $max_size;
    my $ssh2 = $self->session;
    my $old_blocking = $ssh2->blocking;
    my $timeout = $ssh2->timeout;
    my $delay = (($timeout and $timeout < 2000) ? 0.0005 * $timeout : 1);
    my $deadline;
    $deadline = time + 1 + 0.001 * $timeout if $timeout;
    $ssh2->blocking(0);
    while (1) {
        my @out;
        my $bytes;
        my $fail;
        my $zero;
        for (0, 1) {
            my $rc = $self->read($out[$_], $max_size, $_);
            if (defined $rc) {
                $rc or $zero++;
                $bytes += $rc;
                $deadline = time + 1 + 0.001 * $timeout if $timeout;
            }
            else {
                $out[$_] = '';
                if ($ssh2->error != Net::SSH2::LIBSSH2_ERROR_EAGAIN()) {
                    $fail++;
                    last;
                }
            }
        }
        if ($bytes or $self->eof) {
            $ssh2->blocking($old_blocking);
            return (wantarray ? @out : $out[0])
        }
        if ($fail) {
            $ssh2->blocking($old_blocking);
            return;
        }
        unless ($zero) {
            return unless $old_blocking;
            if ($deadline and time > $deadline) {
                $ssh2->_set_error(Net::SSH2::LIBSSH2_ERROR_TIMEOUT(), "Time out waiting for data");
                return;
            }
            return if time > $deadline;
            my $sock = $ssh2->sock;
            my $fn = fileno($sock);
            my ($rbm, $wbm) = ('', '');
            my $bd = $ssh2->block_directions;
            vec($rbm, $fn, 1) = 1 if $bd & Net::SSH2::LIBSSH2_SESSION_BLOCK_INBOUND();
            vec($wbm, $fn, 1) = 1 if $bd & Net::SSH2::LIBSSH2_SESSION_BLOCK_OUTBOUND();
            select $rbm, $wbm, undef, $delay;
        }
    }
}

sub readline {
    my ($self, $ext, $eol) = @_;
    return if $self->eof;
    $ext ||= 0;
    $eol = $/ unless defined $eol;
    if (wantarray) {
        my $data = '';
        my $buffer;
        while (1) {
            my $bytes = $self->read($buffer, 32768, $ext);
            last unless defined $bytes;
            $data .= $buffer;
        }
        return split /(?<=\Q$eol\E)/s, $data;
    }
    else {
        my $data = '';
        while (1) {
            my $c = $self->getc($ext);
            last unless defined $c;
            $data .= $c;
            last if $data =~ /\Q$eol\E\z/;
        }
        return (length $data ? $data : undef);
    }
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
    $self->write(substr($buf, $offset || 0, $len))
}

sub READLINE { shift->readline(0, $/) }

sub READ {
    my ($self, undef, $len, $offset) = @_;
    my $bytes = $self->read(my($buffer), $len);
    substr($_[1], $offset || 0) = $buffer
        if defined $bytes;
    return $bytes;
}

sub BINMODE {}

*CLOSE = \&close;
*EOF = \&eof;
*GETC = \&getc;

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
as being an object, it is also a tied filehandle.

=head2 setenv ( key, value ... )

Sets remote environment variables. Note that most servers do not allow
environment variables to be freely set.

Pass in a list of keys and values with the values to set.

It returns a true value if all the given environment variables were
correctly set.

=head2 blocking ( flag )

Enable or disable blocking.

Note that this is currently implemented in libssh2 by setting a
per-session flag. It's equivalent to L<Net::SSH2::blocking>.

=head2 eof

Returns true if the remote server sent an EOF.

=head2 send_eof

Sends an EOF to the remote side.

After an EOF has been sent, no more data may be
sent to the remote process C<STDIN> channel.

=head2 close

Close the channel (happens automatically on object destruction).

=head2 wait_closed

Wait for a remote close event. Must have already seen remote EOF.

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

Keep data in separate channels; C<STDERR> is read separately.

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

=head2 read ( buffer, max_size [, ext ] )

Attempts to read up to C<max_size> bytes from the channel into C<buffer>. If
C<ext> is true, reads from the extended data channel (C<STDERR>).

The method returns as soon as some data is available, even if the
given size has not been reached.

Returns number of bytes read or C<undef> on failure. Note that 0 is a
valid return code.

=head2 read2 ( [max_size] )

Attempts to read from both the ordinary (stdout) and the extended
(stderr) channel streams.

Returns two scalars with the data read both from stdout and stderr. It
returns as soon as some data is available and any of the returned
values may be an empty string.

When some error happens it returns the empty list.

Example:

  my ($out, $err) = ('', '');
  while (!$channel->eof) {
      if (my ($o, $e) = $channel->read2) {
          $out .= $o;
          $err .= $e;
      }
      else {
          $ssh2->die_with_error;
      }
  }
  print "STDOUT:\n$out\nSTDERR:\n$err\n";

=head2 readline ( [ext [, eol ] ] )

Reads the next line from the selected stream (C<ext> defaults to 0:
stdout).

C<$/> is used as the end of line marker when C<eol> is C<undef>.

In list context reads and returns all the remaining lines until some
read error happens or the remote side sends an eof.

=head2 getc( [ext] )

Reads and returns the next character from the selected stream.

Returns C<undef> on error.

Note that due to some libssh2 quirks, the return value can be the
empty string which may indicate an EOF condition (but not
always!). See L</eof>.

=head2 write ( buffer )

Send the data in C<buffer> through the channel. Returns number of
bytes written, undef on failure.

In versions of this module prior to 0.57, when working in non-blocking
mode, the would-block condition was signaled by returning
C<LIBSSH2_ERROR_EAGAIN> (a negative number) while leaving the session
error status unset. From version 0.59, C<undef> is returned and the
session error status is set to C<LIBSSH2_ERROR_EAGAIN> as for any
other error.

In non-blocking mode, if C<write> fails with a C<LIBSSH2_ERROR_EAGAIN>
error, no other operation must be invoked over any object in the same
SSH session besides L</sock> and L<blocking_directions>.

Once the socket becomes ready again, the exact same former C<write>
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
