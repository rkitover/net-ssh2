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

This method dies when some error happens. On success it returns the
number or entries read.

=head2 writefile (filename)

Saves the known host entries to the given file.

This method dies when some error happens.

=head2 add (hostname, salt, key, comment, key_type|host_format|key_format)

Add a host and its associated key to the collection of known hosts.

The C<host_format> argument specifies the format of the given host:

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

This method dies when some error happens.

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

The documentation on this file is based on the comments inside
C<libssh2.h> file from the libssh2 distribution which has the
following copyright and license:

Copyright (c) 2004-2009, Sara Golemon <sarag@libssh2.org>
Copyright (c) 2009-2012 Daniel Stenberg
Copyright (c) 2010 Simon Josefsson <simon@josefsson.org>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

Neither the name of the copyright holder nor the names of any other
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

=cut
