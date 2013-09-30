package Net::SSH2::KnownHosts;

use strict;
use warnings;

1;
__END__

=head1 NAME

Net::SSH2::KnownHosts - SSH 2 knownhosts object

=head1 DESCRIPTION

The C<knownhosts> object allows one to manipulate the entries in the
C<known_host> file usually located at C<~/.ssh/known_hosts> and which
contains the public keys of the already known hosts.

The methods currently supported are as follows:

=head2 readfile (filename)

Populates the object with the entries in the given file.

=head2 writefile (filename)

Saves the known host entries to the given file.

=head2 add (hostname, salt, key, comment, key_type|host_format|key_format)

Add a host and its associated key to the collection of known hosts.

The C<host_format> argument specifies on what format the given host:

    LIBSSH2_KNOWNHOST_TYPE_PLAIN  - ascii "hostname.domain.tld"
    LIBSSH2_KNOWNHOST_TYPE_SHA1   - SHA1(salt, host) base64-encoded!
    LIBSSH2_KNOWNHOST_TYPE_CUSTOM - another hash

If C<SHA1> is selected as host format, the salt must be provided to
the salt argument. This too base64 encoded.

The SHA-1 hash is what OpenSSH can be told to use in known_hosts
files. If a custom type is used, salt is ignored and you must provide
the host pre-hashed when checking for it in the C<check> method.

The available key formats are as follow:

    LIBSSH2_KNOWNHOST_KEYENC_RAW
    LIBSSH2_KNOWNHOST_KEYENC_BASE64

Fnally, the available key types are as follow:

    LIBSSH2_KNOWNHOST_KEY_RSA1
    LIBSSH2_KNOWNHOST_KEY_SSHRSA
    LIBSSH2_KNOWNHOST_KEY_SSHDSS

The comment argument may be undef.

=head2 check (hostname, port, key, key_type|host_format|key_format)

Check a host and its associated key against the collection of known hosts.

The C<key_type|host_format|key_format> argument has the same meaning
as in the L</add> method.

C<undef> may be passed as the port argument.

Returns:

    LIBSSH2_KNOWNHOST_CHECK_MATCH    (0)
    LIBSSH2_KNOWNHOST_CHECK_MISMATCH (1)
    LIBSSH2_KNOWNHOST_CHECK_NOTFOUND (2)
    LIBSSH2_KNOWNHOST_CHECK_FAILURE  (3)

=head1 SEE ALSO

L<Net::SSH2>, L<sshd(8)>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 Salvador FandiE<ntilde>o; all rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.0 or,
at your option, any later version of Perl 5 you may have available.

=cut
