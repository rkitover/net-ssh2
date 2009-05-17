#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_17 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_FXF_CREAT LIBSSH2_FXF_TRUNC LIBSSH2_FXF_WRITE LIBSSH2_SFTP_STAT */
  /* Offset 14 gives the best switch position.  */
  switch (name[14]) {
  case 'E':
    if (memEQ(name, "LIBSSH2_FXF_CREAT", 17)) {
    /*                             ^         */
#ifdef LIBSSH2_FXF_CREAT
      *iv_return = LIBSSH2_FXF_CREAT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_FXF_WRITE", 17)) {
    /*                             ^         */
#ifdef LIBSSH2_FXF_WRITE
      *iv_return = LIBSSH2_FXF_WRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_SFTP_STAT", 17)) {
    /*                             ^         */
#ifdef LIBSSH2_SFTP_STAT
      *iv_return = LIBSSH2_SFTP_STAT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "LIBSSH2_FXF_TRUNC", 17)) {
    /*                             ^         */
#ifdef LIBSSH2_FXF_TRUNC
      *iv_return = LIBSSH2_FXF_TRUNC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_ERROR_FILE LIBSSH2_ERROR_ZLIB LIBSSH2_FXF_APPEND
     LIBSSH2_FX_FAILURE LIBSSH2_METHOD_KEX LIBSSH2_SFTP_LSTAT
     LIBSSH2_TERM_WIDTH */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'D':
    if (memEQ(name, "LIBSSH2_TERM_WIDTH", 18)) {
    /*                              ^         */
#ifdef LIBSSH2_TERM_WIDTH
      *iv_return = LIBSSH2_TERM_WIDTH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LIBSSH2_FXF_APPEND", 18)) {
    /*                              ^         */
#ifdef LIBSSH2_FXF_APPEND
      *iv_return = LIBSSH2_FXF_APPEND;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_ERROR_FILE", 18)) {
    /*                              ^         */
#ifdef LIBSSH2_ERROR_FILE
      *iv_return = LIBSSH2_ERROR_FILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "LIBSSH2_METHOD_KEX", 18)) {
    /*                              ^         */
#ifdef LIBSSH2_METHOD_KEX
      *iv_return = LIBSSH2_METHOD_KEX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_ERROR_ZLIB", 18)) {
    /*                              ^         */
#ifdef LIBSSH2_ERROR_ZLIB
      *iv_return = LIBSSH2_ERROR_ZLIB;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_SFTP_LSTAT", 18)) {
    /*                              ^         */
#ifdef LIBSSH2_SFTP_LSTAT
      *iv_return = LIBSSH2_SFTP_LSTAT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "LIBSSH2_FX_FAILURE", 18)) {
    /*                              ^         */
#ifdef LIBSSH2_FX_FAILURE
      *iv_return = LIBSSH2_FX_FAILURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_ERROR_ALLOC LIBSSH2_ERROR_INVAL LIBSSH2_ERROR_PROTO
     LIBSSH2_FX_NO_MEDIA LIBSSH2_TERM_HEIGHT */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'E':
    if (memEQ(name, "LIBSSH2_FX_NO_MEDIA", 19)) {
    /*                              ^          */
#ifdef LIBSSH2_FX_NO_MEDIA
      *iv_return = LIBSSH2_FX_NO_MEDIA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_TERM_HEIGHT", 19)) {
    /*                              ^          */
#ifdef LIBSSH2_TERM_HEIGHT
      *iv_return = LIBSSH2_TERM_HEIGHT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_ERROR_ALLOC", 19)) {
    /*                              ^          */
#ifdef LIBSSH2_ERROR_ALLOC
      *iv_return = LIBSSH2_ERROR_ALLOC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_ERROR_INVAL", 19)) {
    /*                              ^          */
#ifdef LIBSSH2_ERROR_INVAL
      *iv_return = LIBSSH2_ERROR_INVAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "LIBSSH2_ERROR_PROTO", 19)) {
    /*                              ^          */
#ifdef LIBSSH2_ERROR_PROTO
      *iv_return = LIBSSH2_ERROR_PROTO;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_20 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_CALLBACK_X11 LIBSSH2_FLAG_SIGPIPE LIBSSH2_FX_LINK_LOOP
     LIBSSH2_SFTP_OPENDIR LIBSSH2_SFTP_SETSTAT LIBSSH2_SFTP_SYMLINK
     LIBSSH2_SFTP_VERSION */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'E':
    if (memEQ(name, "LIBSSH2_SFTP_OPENDIR", 20)) {
    /*                              ^           */
#ifdef LIBSSH2_SFTP_OPENDIR
      *iv_return = LIBSSH2_SFTP_OPENDIR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "LIBSSH2_FLAG_SIGPIPE", 20)) {
    /*                              ^           */
#ifdef LIBSSH2_FLAG_SIGPIPE
      *iv_return = LIBSSH2_FLAG_SIGPIPE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "LIBSSH2_CALLBACK_X11", 20)) {
    /*                              ^           */
#ifdef LIBSSH2_CALLBACK_X11
      *iv_return = LIBSSH2_CALLBACK_X11;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "LIBSSH2_SFTP_SYMLINK", 20)) {
    /*                              ^           */
#ifdef LIBSSH2_SFTP_SYMLINK
      *iv_return = LIBSSH2_SFTP_SYMLINK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "LIBSSH2_SFTP_VERSION", 20)) {
    /*                              ^           */
#ifdef LIBSSH2_SFTP_VERSION
      *iv_return = LIBSSH2_SFTP_VERSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_SFTP_SETSTAT", 20)) {
    /*                              ^           */
#ifdef LIBSSH2_SFTP_SETSTAT
      *iv_return = LIBSSH2_SFTP_SETSTAT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "LIBSSH2_FX_LINK_LOOP", 20)) {
    /*                              ^           */
#ifdef LIBSSH2_FX_LINK_LOOP
      *iv_return = LIBSSH2_FX_LINK_LOOP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_ERROR_DECRYPT LIBSSH2_ERROR_TIMEOUT LIBSSH2_METHOD_MAC_CS
     LIBSSH2_METHOD_MAC_SC LIBSSH2_POLLFD_POLLEX LIBSSH2_POLLFD_POLLIN
     LIBSSH2_POLLFD_SOCKET LIBSSH2_SFTP_OPENFILE LIBSSH2_SFTP_READLINK
     LIBSSH2_SFTP_REALPATH LIBSSH2_TERM_WIDTH_PX */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'C':
    if (memEQ(name, "LIBSSH2_METHOD_MAC_CS", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_METHOD_MAC_CS
      *iv_return = LIBSSH2_METHOD_MAC_CS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LIBSSH2_POLLFD_POLLEX", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_POLLFD_POLLEX
      *iv_return = LIBSSH2_POLLFD_POLLEX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_POLLFD_SOCKET", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_POLLFD_SOCKET
      *iv_return = LIBSSH2_POLLFD_SOCKET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_POLLFD_POLLIN", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_POLLFD_POLLIN
      *iv_return = LIBSSH2_POLLFD_POLLIN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_SFTP_OPENFILE", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_SFTP_OPENFILE
      *iv_return = LIBSSH2_SFTP_OPENFILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_SFTP_READLINK", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_SFTP_READLINK
      *iv_return = LIBSSH2_SFTP_READLINK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "LIBSSH2_ERROR_DECRYPT", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_ERROR_DECRYPT
      *iv_return = LIBSSH2_ERROR_DECRYPT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_TERM_WIDTH_PX", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_TERM_WIDTH_PX
      *iv_return = LIBSSH2_TERM_WIDTH_PX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "LIBSSH2_METHOD_MAC_SC", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_METHOD_MAC_SC
      *iv_return = LIBSSH2_METHOD_MAC_SC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_SFTP_REALPATH", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_SFTP_REALPATH
      *iv_return = LIBSSH2_SFTP_REALPATH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "LIBSSH2_ERROR_TIMEOUT", 21)) {
    /*                                  ^        */
#ifdef LIBSSH2_ERROR_TIMEOUT
      *iv_return = LIBSSH2_ERROR_TIMEOUT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_CALLBACK_DEBUG LIBSSH2_FX_BAD_MESSAGE LIBSSH2_METHOD_COMP_CS
     LIBSSH2_METHOD_COMP_SC LIBSSH2_METHOD_HOSTKEY LIBSSH2_METHOD_LANG_CS
     LIBSSH2_METHOD_LANG_SC LIBSSH2_PACKET_MAXCOMP LIBSSH2_POLLFD_CHANNEL
     LIBSSH2_POLLFD_POLLERR LIBSSH2_POLLFD_POLLEXT LIBSSH2_POLLFD_POLLHUP
     LIBSSH2_POLLFD_POLLOUT LIBSSH2_POLLFD_POLLPRI LIBSSH2_SFTP_ATTR_SIZE
     LIBSSH2_SFTP_TYPE_FIFO LIBSSH2_TERM_HEIGHT_PX */
  /* Offset 21 gives the best switch position.  */
  switch (name[21]) {
  case 'C':
    if (memEQ(name, "LIBSSH2_METHOD_COMP_S", 21)) {
    /*                                    C      */
#ifdef LIBSSH2_METHOD_COMP_SC
      *iv_return = LIBSSH2_METHOD_COMP_SC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_METHOD_LANG_S", 21)) {
    /*                                    C      */
#ifdef LIBSSH2_METHOD_LANG_SC
      *iv_return = LIBSSH2_METHOD_LANG_SC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LIBSSH2_FX_BAD_MESSAG", 21)) {
    /*                                    E      */
#ifdef LIBSSH2_FX_BAD_MESSAGE
      *iv_return = LIBSSH2_FX_BAD_MESSAGE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_SFTP_ATTR_SIZ", 21)) {
    /*                                    E      */
#ifdef LIBSSH2_SFTP_ATTR_SIZE
      *iv_return = LIBSSH2_SFTP_ATTR_SIZE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "LIBSSH2_CALLBACK_DEBU", 21)) {
    /*                                    G      */
#ifdef LIBSSH2_CALLBACK_DEBUG
      *iv_return = LIBSSH2_CALLBACK_DEBUG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_POLLFD_POLLPR", 21)) {
    /*                                    I      */
#ifdef LIBSSH2_POLLFD_POLLPRI
      *iv_return = LIBSSH2_POLLFD_POLLPRI;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_POLLFD_CHANNE", 21)) {
    /*                                    L      */
#ifdef LIBSSH2_POLLFD_CHANNEL
      *iv_return = LIBSSH2_POLLFD_CHANNEL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_FIF", 21)) {
    /*                                    O      */
#ifdef LIBSSH2_SFTP_TYPE_FIFO
      *iv_return = LIBSSH2_SFTP_TYPE_FIFO;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "LIBSSH2_PACKET_MAXCOM", 21)) {
    /*                                    P      */
#ifdef LIBSSH2_PACKET_MAXCOMP
      *iv_return = LIBSSH2_PACKET_MAXCOMP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_POLLFD_POLLHU", 21)) {
    /*                                    P      */
#ifdef LIBSSH2_POLLFD_POLLHUP
      *iv_return = LIBSSH2_POLLFD_POLLHUP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "LIBSSH2_POLLFD_POLLER", 21)) {
    /*                                    R      */
#ifdef LIBSSH2_POLLFD_POLLERR
      *iv_return = LIBSSH2_POLLFD_POLLERR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "LIBSSH2_METHOD_COMP_C", 21)) {
    /*                                    S      */
#ifdef LIBSSH2_METHOD_COMP_CS
      *iv_return = LIBSSH2_METHOD_COMP_CS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_METHOD_LANG_C", 21)) {
    /*                                    S      */
#ifdef LIBSSH2_METHOD_LANG_CS
      *iv_return = LIBSSH2_METHOD_LANG_CS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_POLLFD_POLLEX", 21)) {
    /*                                    T      */
#ifdef LIBSSH2_POLLFD_POLLEXT
      *iv_return = LIBSSH2_POLLFD_POLLEXT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_POLLFD_POLLOU", 21)) {
    /*                                    T      */
#ifdef LIBSSH2_POLLFD_POLLOUT
      *iv_return = LIBSSH2_POLLFD_POLLOUT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "LIBSSH2_TERM_HEIGHT_P", 21)) {
    /*                                    X      */
#ifdef LIBSSH2_TERM_HEIGHT_PX
      *iv_return = LIBSSH2_TERM_HEIGHT_PX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "LIBSSH2_METHOD_HOSTKE", 21)) {
    /*                                    Y      */
#ifdef LIBSSH2_METHOD_HOSTKEY
      *iv_return = LIBSSH2_METHOD_HOSTKEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_23 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_CALLBACK_IGNORE LIBSSH2_DH_GEX_MAXGROUP LIBSSH2_DH_GEX_MINGROUP
     LIBSSH2_DH_GEX_OPTGROUP LIBSSH2_FX_NO_SUCH_FILE LIBSSH2_FX_NO_SUCH_PATH
     LIBSSH2_METHOD_CRYPT_CS LIBSSH2_METHOD_CRYPT_SC LIBSSH2_POLLFD_LISTENER
     LIBSSH2_POLLFD_POLLNVAL */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case 'H':
    if (memEQ(name, "LIBSSH2_FX_NO_SUCH_FILE", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_FX_NO_SUCH_FILE
      *iv_return = LIBSSH2_FX_NO_SUCH_FILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_FX_NO_SUCH_PATH", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_FX_NO_SUCH_PATH
      *iv_return = LIBSSH2_FX_NO_SUCH_PATH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_CALLBACK_IGNORE", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_CALLBACK_IGNORE
      *iv_return = LIBSSH2_CALLBACK_IGNORE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_POLLFD_POLLNVAL", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_POLLFD_POLLNVAL
      *iv_return = LIBSSH2_POLLFD_POLLNVAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_DH_GEX_MINGROUP", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_DH_GEX_MINGROUP
      *iv_return = LIBSSH2_DH_GEX_MINGROUP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "LIBSSH2_POLLFD_LISTENER", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_POLLFD_LISTENER
      *iv_return = LIBSSH2_POLLFD_LISTENER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_DH_GEX_OPTGROUP", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_DH_GEX_OPTGROUP
      *iv_return = LIBSSH2_DH_GEX_OPTGROUP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "LIBSSH2_DH_GEX_MAXGROUP", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_DH_GEX_MAXGROUP
      *iv_return = LIBSSH2_DH_GEX_MAXGROUP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "LIBSSH2_METHOD_CRYPT_CS", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_METHOD_CRYPT_CS
      *iv_return = LIBSSH2_METHOD_CRYPT_CS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_METHOD_CRYPT_SC", 23)) {
    /*                                ^            */
#ifdef LIBSSH2_METHOD_CRYPT_SC
      *iv_return = LIBSSH2_METHOD_CRYPT_SC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_24 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_FX_DIR_NOT_EMPTY LIBSSH2_FX_LOCK_CONFlICT LIBSSH2_FX_NO_CONNECTION
     LIBSSH2_FX_WRITE_PROTECT LIBSSH2_HOSTKEY_HASH_MD5 LIBSSH2_PACKET_MAXDECOMP
     LIBSSH2_SFTP_ATTR_UIDGID LIBSSH2_SFTP_TYPE_SOCKET */
  /* Offset 16 gives the best switch position.  */
  switch (name[16]) {
  case 'A':
    if (memEQ(name, "LIBSSH2_PACKET_MAXDECOMP", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_PACKET_MAXDECOMP
      *iv_return = LIBSSH2_PACKET_MAXDECOMP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "LIBSSH2_FX_LOCK_CONFlICT", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_FX_LOCK_CONFlICT
      *iv_return = LIBSSH2_FX_LOCK_CONFlICT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_SOCKET", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_SFTP_TYPE_SOCKET
      *iv_return = LIBSSH2_SFTP_TYPE_SOCKET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "LIBSSH2_HOSTKEY_HASH_MD5", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_HOSTKEY_HASH_MD5
      *iv_return = LIBSSH2_HOSTKEY_HASH_MD5;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_FX_NO_CONNECTION", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_FX_NO_CONNECTION
      *iv_return = LIBSSH2_FX_NO_CONNECTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "LIBSSH2_FX_DIR_NOT_EMPTY", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_FX_DIR_NOT_EMPTY
      *iv_return = LIBSSH2_FX_DIR_NOT_EMPTY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "LIBSSH2_SFTP_ATTR_UIDGID", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_SFTP_ATTR_UIDGID
      *iv_return = LIBSSH2_SFTP_ATTR_UIDGID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "LIBSSH2_FX_WRITE_PROTECT", 24)) {
    /*                               ^              */
#ifdef LIBSSH2_FX_WRITE_PROTECT
      *iv_return = LIBSSH2_FX_WRITE_PROTECT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_CALLBACK_MACERROR LIBSSH2_CHANNEL_FLUSH_ALL
     LIBSSH2_CHANNEL_MINADJUST LIBSSH2_ERROR_BANNER_NONE
     LIBSSH2_ERROR_BANNER_SEND LIBSSH2_ERROR_INVALID_MAC
     LIBSSH2_ERROR_KEX_FAILURE LIBSSH2_ERROR_METHOD_NONE
     LIBSSH2_ERROR_SOCKET_NONE LIBSSH2_ERROR_SOCKET_SEND
     LIBSSH2_FX_INVALID_HANDLE LIBSSH2_FX_OP_UNSUPPORTED
     LIBSSH2_FX_QUOTA_EXCEEDED LIBSSH2_HOSTKEY_HASH_SHA1
     LIBSSH2_PACKET_MAXPAYLOAD LIBSSH2_SFTP_TYPE_REGULAR
     LIBSSH2_SFTP_TYPE_SPECIAL LIBSSH2_SFTP_TYPE_SYMLINK
     LIBSSH2_SFTP_TYPE_UNKNOWN */
  /* Offset 16 gives the best switch position.  */
  switch (name[16]) {
  case 'A':
    if (memEQ(name, "LIBSSH2_PACKET_MAXPAYLOAD", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_PACKET_MAXPAYLOAD
      *iv_return = LIBSSH2_PACKET_MAXPAYLOAD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "LIBSSH2_ERROR_SOCKET_NONE", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_ERROR_SOCKET_NONE
      *iv_return = LIBSSH2_ERROR_SOCKET_NONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_ERROR_SOCKET_SEND", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_ERROR_SOCKET_SEND
      *iv_return = LIBSSH2_ERROR_SOCKET_SEND;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_REGULAR", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_SFTP_TYPE_REGULAR
      *iv_return = LIBSSH2_SFTP_TYPE_REGULAR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_SPECIAL", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_SFTP_TYPE_SPECIAL
      *iv_return = LIBSSH2_SFTP_TYPE_SPECIAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_SYMLINK", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_SFTP_TYPE_SYMLINK
      *iv_return = LIBSSH2_SFTP_TYPE_SYMLINK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_UNKNOWN", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_SFTP_TYPE_UNKNOWN
      *iv_return = LIBSSH2_SFTP_TYPE_UNKNOWN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "LIBSSH2_CHANNEL_FLUSH_ALL", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_CHANNEL_FLUSH_ALL
      *iv_return = LIBSSH2_CHANNEL_FLUSH_ALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "LIBSSH2_HOSTKEY_HASH_SHA1", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_HOSTKEY_HASH_SHA1
      *iv_return = LIBSSH2_HOSTKEY_HASH_SHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_FX_INVALID_HANDLE", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_FX_INVALID_HANDLE
      *iv_return = LIBSSH2_FX_INVALID_HANDLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "LIBSSH2_CHANNEL_MINADJUST", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_CHANNEL_MINADJUST
      *iv_return = LIBSSH2_CHANNEL_MINADJUST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_ERROR_BANNER_NONE", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_ERROR_BANNER_NONE
      *iv_return = LIBSSH2_ERROR_BANNER_NONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_ERROR_BANNER_SEND", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_ERROR_BANNER_SEND
      *iv_return = LIBSSH2_ERROR_BANNER_SEND;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "LIBSSH2_FX_OP_UNSUPPORTED", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_FX_OP_UNSUPPORTED
      *iv_return = LIBSSH2_FX_OP_UNSUPPORTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_ERROR_METHOD_NONE", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_ERROR_METHOD_NONE
      *iv_return = LIBSSH2_ERROR_METHOD_NONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "LIBSSH2_ERROR_INVALID_MAC", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_ERROR_INVALID_MAC
      *iv_return = LIBSSH2_ERROR_INVALID_MAC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "LIBSSH2_ERROR_KEX_FAILURE", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_ERROR_KEX_FAILURE
      *iv_return = LIBSSH2_ERROR_KEX_FAILURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "LIBSSH2_CALLBACK_MACERROR", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_CALLBACK_MACERROR
      *iv_return = LIBSSH2_CALLBACK_MACERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_FX_QUOTA_EXCEEDED", 25)) {
    /*                               ^               */
#ifdef LIBSSH2_FX_QUOTA_EXCEEDED
      *iv_return = LIBSSH2_FX_QUOTA_EXCEEDED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_26 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_ERROR_HOSTKEY_INIT LIBSSH2_ERROR_HOSTKEY_SIGN
     LIBSSH2_ERROR_SCP_PROTOCOL LIBSSH2_FX_CONNECTION_LOST
     LIBSSH2_FX_NOT_A_DIRECTORY LIBSSH2_SFTP_ATTR_EXTENDED
     LIBSSH2_SFTP_PACKET_MAXLEN LIBSSH2_SFTP_RENAME_ATOMIC
     LIBSSH2_SFTP_RENAME_NATIVE LIBSSH2_SOCKET_POLL_UDELAY */
  /* Offset 22 gives the best switch position.  */
  switch (name[22]) {
  case 'E':
    if (memEQ(name, "LIBSSH2_SOCKET_POLL_UDELAY", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_SOCKET_POLL_UDELAY
      *iv_return = LIBSSH2_SOCKET_POLL_UDELAY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_ERROR_HOSTKEY_INIT", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_ERROR_HOSTKEY_INIT
      *iv_return = LIBSSH2_ERROR_HOSTKEY_INIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_FX_CONNECTION_LOST", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_FX_CONNECTION_LOST
      *iv_return = LIBSSH2_FX_CONNECTION_LOST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_SFTP_ATTR_EXTENDED", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_SFTP_ATTR_EXTENDED
      *iv_return = LIBSSH2_SFTP_ATTR_EXTENDED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "LIBSSH2_ERROR_SCP_PROTOCOL", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_ERROR_SCP_PROTOCOL
      *iv_return = LIBSSH2_ERROR_SCP_PROTOCOL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_SFTP_RENAME_ATOMIC", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_SFTP_RENAME_ATOMIC
      *iv_return = LIBSSH2_SFTP_RENAME_ATOMIC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "LIBSSH2_ERROR_HOSTKEY_SIGN", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_ERROR_HOSTKEY_SIGN
      *iv_return = LIBSSH2_ERROR_HOSTKEY_SIGN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_FX_NOT_A_DIRECTORY", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_FX_NOT_A_DIRECTORY
      *iv_return = LIBSSH2_FX_NOT_A_DIRECTORY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_SFTP_RENAME_NATIVE", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_SFTP_RENAME_NATIVE
      *iv_return = LIBSSH2_SFTP_RENAME_NATIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "LIBSSH2_SFTP_PACKET_MAXLEN", 26)) {
    /*                                     ^          */
#ifdef LIBSSH2_SFTP_PACKET_MAXLEN
      *iv_return = LIBSSH2_SFTP_PACKET_MAXLEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_27 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_CALLBACK_DISCONNECT LIBSSH2_ERROR_SFTP_PROTOCOL
     LIBSSH2_FX_INVALID_FILENAME LIBSSH2_SFTP_ATTR_ACMODTIME
     LIBSSH2_SFTP_TYPE_DIRECTORY */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'F':
    if (memEQ(name, "LIBSSH2_ERROR_SFTP_PROTOCOL", 27)) {
    /*                              ^                  */
#ifdef LIBSSH2_ERROR_SFTP_PROTOCOL
      *iv_return = LIBSSH2_ERROR_SFTP_PROTOCOL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "LIBSSH2_CALLBACK_DISCONNECT", 27)) {
    /*                              ^                  */
#ifdef LIBSSH2_CALLBACK_DISCONNECT
      *iv_return = LIBSSH2_CALLBACK_DISCONNECT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_FX_INVALID_FILENAME", 27)) {
    /*                              ^                  */
#ifdef LIBSSH2_FX_INVALID_FILENAME
      *iv_return = LIBSSH2_FX_INVALID_FILENAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_DIRECTORY", 27)) {
    /*                              ^                  */
#ifdef LIBSSH2_SFTP_TYPE_DIRECTORY
      *iv_return = LIBSSH2_SFTP_TYPE_DIRECTORY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_SFTP_ATTR_ACMODTIME", 27)) {
    /*                              ^                  */
#ifdef LIBSSH2_SFTP_ATTR_ACMODTIME
      *iv_return = LIBSSH2_SFTP_ATTR_ACMODTIME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_28 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_ERROR_CHANNEL_CLOSED LIBSSH2_ERROR_REQUEST_DENIED
     LIBSSH2_ERROR_SOCKET_TIMEOUT LIBSSH2_FX_PERMISSION_DENIED
     LIBSSH2_FX_UNKNOWN_PRINCIPLE LIBSSH2_SOCKET_POLL_MAXLOOPS */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'L':
    if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_CLOSED", 28)) {
    /*                                   ^              */
#ifdef LIBSSH2_ERROR_CHANNEL_CLOSED
      *iv_return = LIBSSH2_ERROR_CHANNEL_CLOSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "LIBSSH2_SOCKET_POLL_MAXLOOPS", 28)) {
    /*                                   ^              */
#ifdef LIBSSH2_SOCKET_POLL_MAXLOOPS
      *iv_return = LIBSSH2_SOCKET_POLL_MAXLOOPS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_FX_PERMISSION_DENIED", 28)) {
    /*                                   ^              */
#ifdef LIBSSH2_FX_PERMISSION_DENIED
      *iv_return = LIBSSH2_FX_PERMISSION_DENIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "LIBSSH2_FX_UNKNOWN_PRINCIPLE", 28)) {
    /*                                   ^              */
#ifdef LIBSSH2_FX_UNKNOWN_PRINCIPLE
      *iv_return = LIBSSH2_FX_UNKNOWN_PRINCIPLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "LIBSSH2_ERROR_REQUEST_DENIED", 28)) {
    /*                                   ^              */
#ifdef LIBSSH2_ERROR_REQUEST_DENIED
      *iv_return = LIBSSH2_ERROR_REQUEST_DENIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "LIBSSH2_ERROR_SOCKET_TIMEOUT", 28)) {
    /*                                   ^              */
#ifdef LIBSSH2_ERROR_SOCKET_TIMEOUT
      *iv_return = LIBSSH2_ERROR_SOCKET_TIMEOUT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_29 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_ERROR_CHANNEL_FAILURE LIBSSH2_ERROR_CHANNEL_UNKNOWN
     LIBSSH2_POLLFD_CHANNEL_CLOSED LIBSSH2_POLLFD_SESSION_CLOSED
     LIBSSH2_SFTP_ATTR_PERMISSIONS LIBSSH2_SFTP_RENAME_OVERWRITE
     LIBSSH2_SFTP_TYPE_CHAR_DEVICE */
  /* Offset 25 gives the best switch position.  */
  switch (name[25]) {
  case 'I':
    if (memEQ(name, "LIBSSH2_SFTP_ATTR_PERMISSIONS", 29)) {
    /*                                        ^          */
#ifdef LIBSSH2_SFTP_ATTR_PERMISSIONS
      *iv_return = LIBSSH2_SFTP_ATTR_PERMISSIONS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_FAILURE", 29)) {
    /*                                        ^          */
#ifdef LIBSSH2_ERROR_CHANNEL_FAILURE
      *iv_return = LIBSSH2_ERROR_CHANNEL_FAILURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_UNKNOWN", 29)) {
    /*                                        ^          */
#ifdef LIBSSH2_ERROR_CHANNEL_UNKNOWN
      *iv_return = LIBSSH2_ERROR_CHANNEL_UNKNOWN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "LIBSSH2_POLLFD_CHANNEL_CLOSED", 29)) {
    /*                                        ^          */
#ifdef LIBSSH2_POLLFD_CHANNEL_CLOSED
      *iv_return = LIBSSH2_POLLFD_CHANNEL_CLOSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_POLLFD_SESSION_CLOSED", 29)) {
    /*                                        ^          */
#ifdef LIBSSH2_POLLFD_SESSION_CLOSED
      *iv_return = LIBSSH2_POLLFD_SESSION_CLOSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "LIBSSH2_SFTP_RENAME_OVERWRITE", 29)) {
    /*                                        ^          */
#ifdef LIBSSH2_SFTP_RENAME_OVERWRITE
      *iv_return = LIBSSH2_SFTP_RENAME_OVERWRITE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_CHAR_DEVICE", 29)) {
    /*                                        ^          */
#ifdef LIBSSH2_SFTP_TYPE_CHAR_DEVICE
      *iv_return = LIBSSH2_SFTP_TYPE_CHAR_DEVICE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_30 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_CHANNEL_PACKET_DEFAULT LIBSSH2_CHANNEL_WINDOW_DEFAULT
     LIBSSH2_ERROR_CHANNEL_EOF_SENT LIBSSH2_ERROR_PASSWORD_EXPIRED
     LIBSSH2_FX_FILE_ALREADY_EXISTS LIBSSH2_POLLFD_LISTENER_CLOSED
     LIBSSH2_SFTP_TYPE_BLOCK_DEVICE */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'A':
    if (memEQ(name, "LIBSSH2_FX_FILE_ALREADY_EXISTS", 30)) {
    /*                                   ^                */
#ifdef LIBSSH2_FX_FILE_ALREADY_EXISTS
      *iv_return = LIBSSH2_FX_FILE_ALREADY_EXISTS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LIBSSH2_CHANNEL_PACKET_DEFAULT", 30)) {
    /*                                   ^                */
#ifdef LIBSSH2_CHANNEL_PACKET_DEFAULT
      *iv_return = LIBSSH2_CHANNEL_PACKET_DEFAULT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_EOF_SENT", 30)) {
    /*                                   ^                */
#ifdef LIBSSH2_ERROR_CHANNEL_EOF_SENT
      *iv_return = LIBSSH2_ERROR_CHANNEL_EOF_SENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_POLLFD_LISTENER_CLOSED", 30)) {
    /*                                   ^                */
#ifdef LIBSSH2_POLLFD_LISTENER_CLOSED
      *iv_return = LIBSSH2_POLLFD_LISTENER_CLOSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "LIBSSH2_CHANNEL_WINDOW_DEFAULT", 30)) {
    /*                                   ^                */
#ifdef LIBSSH2_CHANNEL_WINDOW_DEFAULT
      *iv_return = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "LIBSSH2_SFTP_TYPE_BLOCK_DEVICE", 30)) {
    /*                                   ^                */
#ifdef LIBSSH2_SFTP_TYPE_BLOCK_DEVICE
      *iv_return = LIBSSH2_SFTP_TYPE_BLOCK_DEVICE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "LIBSSH2_ERROR_PASSWORD_EXPIRED", 30)) {
    /*                                   ^                */
#ifdef LIBSSH2_ERROR_PASSWORD_EXPIRED
      *iv_return = LIBSSH2_ERROR_PASSWORD_EXPIRED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_34 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE LIBSSH2_ERROR_METHOD_NOT_SUPPORTED
     LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED */
  /* Offset 14 gives the best switch position.  */
  switch (name[14]) {
  case 'K':
    if (memEQ(name, "LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE", 34)) {
    /*                             ^                          */
#ifdef LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE
      *iv_return = LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "LIBSSH2_ERROR_METHOD_NOT_SUPPORTED", 34)) {
    /*                             ^                          */
#ifdef LIBSSH2_ERROR_METHOD_NOT_SUPPORTED
      *iv_return = LIBSSH2_ERROR_METHOD_NOT_SUPPORTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED", 34)) {
    /*                             ^                          */
#ifdef LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED
      *iv_return = LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_36 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL
     LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED
     */
  /* Offset 30 gives the best switch position.  */
  switch (name[30]) {
  case 'D':
    if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED", 36)) {
    /*                                             ^            */
#ifdef LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED
      *iv_return = LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED", 36)) {
    /*                                             ^            */
#ifdef LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED
      *iv_return = LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE", 36)) {
    /*                                             ^            */
#ifdef LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE
      *iv_return = LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL", 36)) {
    /*                                             ^            */
#ifdef LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL
      *iv_return = LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/bin/perl5.8.7 -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(LIBSSH2_CALLBACK_DEBUG LIBSSH2_CALLBACK_DISCONNECT
	       LIBSSH2_CALLBACK_IGNORE LIBSSH2_CALLBACK_MACERROR
	       LIBSSH2_CALLBACK_X11 LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE
	       LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
	       LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL LIBSSH2_CHANNEL_FLUSH_ALL
	       LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA LIBSSH2_CHANNEL_MINADJUST
	       LIBSSH2_CHANNEL_PACKET_DEFAULT LIBSSH2_CHANNEL_WINDOW_DEFAULT
	       LIBSSH2_DH_GEX_MAXGROUP LIBSSH2_DH_GEX_MINGROUP
	       LIBSSH2_DH_GEX_OPTGROUP LIBSSH2_ERROR_ALLOC
	       LIBSSH2_ERROR_BANNER_NONE LIBSSH2_ERROR_BANNER_SEND
	       LIBSSH2_ERROR_CHANNEL_CLOSED LIBSSH2_ERROR_CHANNEL_EOF_SENT
	       LIBSSH2_ERROR_CHANNEL_FAILURE LIBSSH2_ERROR_CHANNEL_OUTOFORDER
	       LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED
	       LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED
	       LIBSSH2_ERROR_CHANNEL_UNKNOWN
	       LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED LIBSSH2_ERROR_DECRYPT
	       LIBSSH2_ERROR_FILE LIBSSH2_ERROR_HOSTKEY_INIT
	       LIBSSH2_ERROR_HOSTKEY_SIGN LIBSSH2_ERROR_INVAL
	       LIBSSH2_ERROR_INVALID_MAC LIBSSH2_ERROR_INVALID_POLL_TYPE
	       LIBSSH2_ERROR_KEX_FAILURE LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE
	       LIBSSH2_ERROR_METHOD_NONE LIBSSH2_ERROR_METHOD_NOT_SUPPORTED
	       LIBSSH2_ERROR_PASSWORD_EXPIRED LIBSSH2_ERROR_PROTO
	       LIBSSH2_ERROR_PUBLICKEY_PROTOCOL
	       LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED
	       LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED LIBSSH2_ERROR_REQUEST_DENIED
	       LIBSSH2_ERROR_SCP_PROTOCOL LIBSSH2_ERROR_SFTP_PROTOCOL
	       LIBSSH2_ERROR_SOCKET_DISCONNECT LIBSSH2_ERROR_SOCKET_NONE
	       LIBSSH2_ERROR_SOCKET_SEND LIBSSH2_ERROR_SOCKET_TIMEOUT
	       LIBSSH2_ERROR_TIMEOUT LIBSSH2_ERROR_ZLIB LIBSSH2_FLAG_SIGPIPE
	       LIBSSH2_FXF_APPEND LIBSSH2_FXF_CREAT LIBSSH2_FXF_EXCL
	       LIBSSH2_FXF_READ LIBSSH2_FXF_TRUNC LIBSSH2_FXF_WRITE
	       LIBSSH2_FX_BAD_MESSAGE LIBSSH2_FX_CONNECTION_LOST
	       LIBSSH2_FX_DIR_NOT_EMPTY LIBSSH2_FX_EOF LIBSSH2_FX_FAILURE
	       LIBSSH2_FX_FILE_ALREADY_EXISTS LIBSSH2_FX_INVALID_FILENAME
	       LIBSSH2_FX_INVALID_HANDLE LIBSSH2_FX_LINK_LOOP
	       LIBSSH2_FX_LOCK_CONFlICT LIBSSH2_FX_NOT_A_DIRECTORY
	       LIBSSH2_FX_NO_CONNECTION LIBSSH2_FX_NO_MEDIA
	       LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM LIBSSH2_FX_NO_SUCH_FILE
	       LIBSSH2_FX_NO_SUCH_PATH LIBSSH2_FX_OK LIBSSH2_FX_OP_UNSUPPORTED
	       LIBSSH2_FX_PERMISSION_DENIED LIBSSH2_FX_QUOTA_EXCEEDED
	       LIBSSH2_FX_UNKNOWN_PRINCIPLE LIBSSH2_FX_WRITE_PROTECT LIBSSH2_H
	       LIBSSH2_HOSTKEY_HASH_MD5 LIBSSH2_HOSTKEY_HASH_SHA1
	       LIBSSH2_METHOD_COMP_CS LIBSSH2_METHOD_COMP_SC
	       LIBSSH2_METHOD_CRYPT_CS LIBSSH2_METHOD_CRYPT_SC
	       LIBSSH2_METHOD_HOSTKEY LIBSSH2_METHOD_KEX LIBSSH2_METHOD_LANG_CS
	       LIBSSH2_METHOD_LANG_SC LIBSSH2_METHOD_MAC_CS
	       LIBSSH2_METHOD_MAC_SC LIBSSH2_PACKET_MAXCOMP
	       LIBSSH2_PACKET_MAXDECOMP LIBSSH2_PACKET_MAXPAYLOAD
	       LIBSSH2_POLLFD_CHANNEL LIBSSH2_POLLFD_CHANNEL_CLOSED
	       LIBSSH2_POLLFD_LISTENER LIBSSH2_POLLFD_LISTENER_CLOSED
	       LIBSSH2_POLLFD_POLLERR LIBSSH2_POLLFD_POLLEX
	       LIBSSH2_POLLFD_POLLEXT LIBSSH2_POLLFD_POLLHUP
	       LIBSSH2_POLLFD_POLLIN LIBSSH2_POLLFD_POLLNVAL
	       LIBSSH2_POLLFD_POLLOUT LIBSSH2_POLLFD_POLLPRI
	       LIBSSH2_POLLFD_SESSION_CLOSED LIBSSH2_POLLFD_SOCKET
	       LIBSSH2_SFTP_ATTR_ACMODTIME LIBSSH2_SFTP_ATTR_EXTENDED
	       LIBSSH2_SFTP_ATTR_PERMISSIONS LIBSSH2_SFTP_ATTR_SIZE
	       LIBSSH2_SFTP_ATTR_UIDGID LIBSSH2_SFTP_LSTAT LIBSSH2_SFTP_OPENDIR
	       LIBSSH2_SFTP_OPENFILE LIBSSH2_SFTP_PACKET_MAXLEN
	       LIBSSH2_SFTP_READLINK LIBSSH2_SFTP_REALPATH
	       LIBSSH2_SFTP_RENAME_ATOMIC LIBSSH2_SFTP_RENAME_NATIVE
	       LIBSSH2_SFTP_RENAME_OVERWRITE LIBSSH2_SFTP_SETSTAT
	       LIBSSH2_SFTP_STAT LIBSSH2_SFTP_SYMLINK
	       LIBSSH2_SFTP_TYPE_BLOCK_DEVICE LIBSSH2_SFTP_TYPE_CHAR_DEVICE
	       LIBSSH2_SFTP_TYPE_DIRECTORY LIBSSH2_SFTP_TYPE_FIFO
	       LIBSSH2_SFTP_TYPE_REGULAR LIBSSH2_SFTP_TYPE_SOCKET
	       LIBSSH2_SFTP_TYPE_SPECIAL LIBSSH2_SFTP_TYPE_SYMLINK
	       LIBSSH2_SFTP_TYPE_UNKNOWN LIBSSH2_SFTP_VERSION
	       LIBSSH2_SOCKET_POLL_MAXLOOPS LIBSSH2_SOCKET_POLL_UDELAY
	       LIBSSH2_TERM_HEIGHT LIBSSH2_TERM_HEIGHT_PX LIBSSH2_TERM_WIDTH
	       LIBSSH2_TERM_WIDTH_PX));

print constant_types(); # macro defs
foreach (C_constant ("Net::SSH2", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "#### XS Section:\n";
print XS_constant ("Net::SSH2", $types);
__END__
   */

  switch (len) {
  case 9:
    if (memEQ(name, "LIBSSH2_H", 9)) {
#ifdef LIBSSH2_H
      *iv_return = LIBSSH2_H;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 13:
    if (memEQ(name, "LIBSSH2_FX_OK", 13)) {
#ifdef LIBSSH2_FX_OK
      *iv_return = LIBSSH2_FX_OK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 14:
    if (memEQ(name, "LIBSSH2_FX_EOF", 14)) {
#ifdef LIBSSH2_FX_EOF
      *iv_return = LIBSSH2_FX_EOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 16:
    /* Names all of length 16.  */
    /* LIBSSH2_FXF_EXCL LIBSSH2_FXF_READ */
    /* Offset 14 gives the best switch position.  */
    switch (name[14]) {
    case 'A':
      if (memEQ(name, "LIBSSH2_FXF_READ", 16)) {
      /*                             ^        */
#ifdef LIBSSH2_FXF_READ
        *iv_return = LIBSSH2_FXF_READ;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'C':
      if (memEQ(name, "LIBSSH2_FXF_EXCL", 16)) {
      /*                             ^        */
#ifdef LIBSSH2_FXF_EXCL
        *iv_return = LIBSSH2_FXF_EXCL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 17:
    return constant_17 (aTHX_ name, iv_return);
    break;
  case 18:
    return constant_18 (aTHX_ name, iv_return);
    break;
  case 19:
    return constant_19 (aTHX_ name, iv_return);
    break;
  case 20:
    return constant_20 (aTHX_ name, iv_return);
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    return constant_23 (aTHX_ name, iv_return);
    break;
  case 24:
    return constant_24 (aTHX_ name, iv_return);
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    return constant_26 (aTHX_ name, iv_return);
    break;
  case 27:
    return constant_27 (aTHX_ name, iv_return);
    break;
  case 28:
    return constant_28 (aTHX_ name, iv_return);
    break;
  case 29:
    return constant_29 (aTHX_ name, iv_return);
    break;
  case 30:
    return constant_30 (aTHX_ name, iv_return);
    break;
  case 31:
    /* Names all of length 31.  */
    /* LIBSSH2_ERROR_INVALID_POLL_TYPE LIBSSH2_ERROR_SOCKET_DISCONNECT */
    /* Offset 15 gives the best switch position.  */
    switch (name[15]) {
    case 'N':
      if (memEQ(name, "LIBSSH2_ERROR_INVALID_POLL_TYPE", 31)) {
      /*                              ^                      */
#ifdef LIBSSH2_ERROR_INVALID_POLL_TYPE
        *iv_return = LIBSSH2_ERROR_INVALID_POLL_TYPE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'O':
      if (memEQ(name, "LIBSSH2_ERROR_SOCKET_DISCONNECT", 31)) {
      /*                              ^                      */
#ifdef LIBSSH2_ERROR_SOCKET_DISCONNECT
        *iv_return = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 32:
    /* Names all of length 32.  */
    /* LIBSSH2_ERROR_CHANNEL_OUTOFORDER LIBSSH2_ERROR_PUBLICKEY_PROTOCOL */
    /* Offset 16 gives the best switch position.  */
    switch (name[16]) {
    case 'A':
      if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_OUTOFORDER", 32)) {
      /*                               ^                      */
#ifdef LIBSSH2_ERROR_CHANNEL_OUTOFORDER
        *iv_return = LIBSSH2_ERROR_CHANNEL_OUTOFORDER;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'B':
      if (memEQ(name, "LIBSSH2_ERROR_PUBLICKEY_PROTOCOL", 32)) {
      /*                               ^                      */
#ifdef LIBSSH2_ERROR_PUBLICKEY_PROTOCOL
        *iv_return = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 33:
    if (memEQ(name, "LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM", 33)) {
#ifdef LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM
      *iv_return = LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 34:
    return constant_34 (aTHX_ name, iv_return);
    break;
  case 35:
    /* Names all of length 35.  */
    /* LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA
       */
    /* Offset 16 gives the best switch position.  */
    switch (name[16]) {
    case 'E':
      if (memEQ(name, "LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE", 35)) {
      /*                               ^                         */
#ifdef LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
        *iv_return = LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'F':
      if (memEQ(name, "LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA", 35)) {
      /*                               ^                         */
#ifdef LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA
        *iv_return = LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 36:
    return constant_36 (aTHX_ name, iv_return);
    break;
  case 37:
    /* Names all of length 37.  */
    /* LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED
       LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED */
    /* Offset 27 gives the best switch position.  */
    switch (name[27]) {
    case 'T':
      if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED", 37)) {
      /*                                          ^                */
#ifdef LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED
        *iv_return = LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'W':
      if (memEQ(name, "LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED", 37)) {
      /*                                          ^                */
#ifdef LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED
        *iv_return = LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

