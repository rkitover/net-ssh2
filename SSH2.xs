/*
 * SSH2.xs - C functions for Net::SSH2
 *
 * D. Robins, 20051022
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define NEED_sv_2pv_flags
#define NEED_newRV_noinc
#define NEED_sv_2pv_nolen
#include "ppport.h"

#if PERL_REVISION == 5 && (PERL_VERSION < 8 || (PERL_VERSION == 8 && PERL_SUBVERSION < 4 ))

#  ifdef SvPVbyte_force
#    undef SvPVbyte_force
#  endif
#  define SvPVbyte_force(sv,lp) SvPV_force(sv,lp)

#  ifdef SvPVbyte_nolen
#    undef SvPVbyte_nolen
#  endif
#  define SvPVbyte_nolen SvPV_nolen

#endif


#include <libssh2.h>
#include <libssh2_sftp.h>
#include <libssh2_publickey.h>

#define LIBSSH2_HOSTKEY_POLICY_STRICT   1
#define LIBSSH2_HOSTKEY_POLICY_ASK      2
#define LIBSSH2_HOSTKEY_POLICY_TOFU     3
#define LIBSSH2_HOSTKEY_POLICY_ADVISORY 4

#define LIBSSH2_EXTENDED_DATA_STDERR    SSH_EXTENDED_DATA_STDERR
#define LIBSSH2_CHANNEL_FLUSH_STDERR    SSH_EXTENDED_DATA_STDERR

#include "const-c.inc"

#if defined(USE_ITHREADS) && (defined(I_PTHREAD) || defined(WIN32))

#ifdef USE_GCRYPT
#define HAVE_GCRYPT
#include <gcrypt.h>
#else /* OpenSSL */
#define HAVE_OPENSSL
#include <openssl/crypto.h>
#endif

#else
/* is #warning portable across C compilers? */
/* NO, an error with -pedantic */
/* #warning "Building a non-threadsafe Net::SSH2" */
#endif

#ifndef MULTIPLICITY
/* for debugging output */
#define my_perl ((void *)0)
#endif

/* constants */

#ifndef LIBSSH2_ERROR_NONE
#define LIBSSH2_ERROR_NONE 0
#endif  /* LIBSSH2_ERROR_NONE */

/* LIBSSH2_ERROR_* values; from 0 continuing negative */
static const char *const xs_libssh2_error[] = {
    "NONE",
    "SOCKET_NONE",
    "BANNER_NONE",
    "BANNER_SEND",
    "INVALID_MAC",
    "KEX_FAILURE",
    "ALLOC",
    "SOCKET_SEND",
    "KEY_EXCHANGE_FAILURE",
    "TIMEOUT",
    "HOSTKEY_INIT",
    "HOSTKEY_SIGN",
    "DECRYPT",
    "SOCKET_DISCONNECT",
    "PROTO",
    "PASSWORD_EXPIRED",
    "FILE",
    "METHOD_NONE",
    "PUBLICKEY_UNRECOGNIZED",
    "PUBLICKEY_UNVERIFIED",
    "CHANNEL_OUTOFORDER",
    "CHANNEL_FAILURE",
    "CHANNEL_REQUEST_DENIED",
    "CHANNEL_UNKNOWN",
    "CHANNEL_WINDOW_EXCEEDED",
    "CHANNEL_PACKET_EXCEEDED",
    "CHANNEL_CLOSED",
    "CHANNEL_EOF_SENT",
    "SCP_PROTOCOL",
    "ZLIB",
    "SOCKET_TIMEOUT",
    "SFTP_PROTOCOL",
    "REQUEST_DENIED",
    "METHOD_NOT_SUPPORTED",
    "INVAL",
    "INVALID_POLL_TYPE",
    "PUBLICKEY_PROTOCOL",
    "EAGAIN",
    "ERROR_BUFFER_TOO_SMALL",
    "BAD_USE",
    "ERROR_COMPRESS",
    "OUT_OF_BOUNDARY",
    "AGENT_PROTOCOL",
    "SOCKET_RECV",
    "ENCRYPT",
    "BAD_SOCKET",
    "KNOWN_HOSTS",
};

/* SSH_FX_* values; from 0 continuing positive */
static const char *const sftp_error[] = {
    "OK",
    "EOF",
    "NO_SUCH_FILE",
    "PERMISSION_DENIED",
    "FAILURE",
    "BAD_MESSAGE",
    "NO_CONNECTION",
    "CONNECTION_LOST",
    "OP_UNSUPPORTED",
    "INVALID_HANDLE",
    "NO_SUCH_PATH",
    "FILE_ALREADY_EXISTS",
    "WRITE_PROTECT",
    "NO_MEDIA",
    "NO_SPACE_ON_FILESYSTEM",
    "QUOTA_EXCEEDED",
    "UNKNOWN_PRINCIPLE",
    "LOCK_CONFLICT",
    "DIR_NOT_EMPTY",
    "NOT_A_DIRECTORY",
    "INVALID_FILENAME",
    "LINK_LOOP"
};

/* private internal functions */

#define countof(x) (sizeof(x)/sizeof(*x))

#define XLATATTR(name, field, flag) \
    else if (strEQ(key, name)) { \
        attrs.field = SvUV(ST(i + 1)); \
        attrs.flags |= LIBSSH2_SFTP_ATTR_##flag; \
    }

typedef int SSH2_RC; /* for converting true/false to 1/undef */
typedef int SSH2_BYTES; /* for functions returning a byte count or a negative number to signal an error */
typedef libssh2_int64_t SSH2_BYTES64; /* the same for unsigned 64bit numbers */
typedef libssh2_uint64_t SSH2_BYTESU64; /* the same for unsigned 64bit numbers */
typedef int SSH2_ERROR; /* for returning SSH2 error numbers */
typedef int SSH2_NERROR; /* for converting SSH2 error code to boolean just indicating success or failure */
typedef int SSH2_BOOL; /* for yes/no responses */

typedef IV SSH2_METHOD;       /* LIBSSH2_METHOD_ constants */
typedef IV SSH2_FLAG;         /* LIBSSH2_FLAG_ constants */
typedef IV SSH2_CALLBACK;     /* LIBSSH2_CALLBACK_ constants */
typedef IV SSH2_HOSTKEY_HASH; /* LIBSSH2_HOSTKEY_HASH_ constants */
typedef IV SSH2_CHANNEL_EXTENDED_DATA; /* SSH2_CHANNEL_EXTENDED_DATA_ constants */
typedef IV SSH2_STREAM_ID;    /* stream_id or LIBSSH2_CHANNEL_FLUSH macros */
typedef char * SSH2_CHARP;         /* string that can not be NULL */
typedef char * SSH2_CHARP_OR_NULL; /* string that can be NULL */

/* Net::SSH2 object */
typedef struct SSH2 {
    LIBSSH2_SESSION* session;
    SV* sv_ss;  /* NB: not set until callback() called */
    SV* socket;
    SV* hostname;
    int port;
    SV* sv_tmp;
    SV* rgsv_cb[LIBSSH2_CALLBACK_X11 + 1];
} SSH2;

/* Net::SSH2::Channel object */
typedef struct SSH2_CHANNEL {
    SSH2* ss;
    SV* sv_ss;
    LIBSSH2_CHANNEL* channel;
} SSH2_CHANNEL;

/* Net::SSH2::SFTP object */
typedef struct SSH2_SFTP {
    SSH2* ss;
    SV* sv_ss;
    LIBSSH2_SFTP* sftp;
} SSH2_SFTP;

/* Net::SSH2::Listener object */
typedef struct SSH2_LISTENER {
    SSH2* ss;
    SV* sv_ss;
    LIBSSH2_LISTENER* listener;
} SSH2_LISTENER;

/* Net::SSH2::File object */
typedef struct SSH2_FILE {
    SSH2_SFTP* sf;
    SV* sv_sf;
    LIBSSH2_SFTP_HANDLE* handle;
} SSH2_FILE;

/* Net::SSH2::Dir object */
typedef struct SSH2_DIR {
    SSH2_SFTP* sf;
    SV* sv_sf;
    LIBSSH2_SFTP_HANDLE* handle;
} SSH2_DIR;

/* Net::SSH2::PublicKey object */
typedef struct SSH2_PUBLICKEY {
    SSH2* ss;
    SV* sv_ss;
    LIBSSH2_PUBLICKEY* pkey;
} SSH2_PUBLICKEY;

#if LIBSSH2_VERSION_NUM >= 0x010200

/* Net::SSH2::KnownHosts object */
typedef struct SSH2_KNOWNHOSTS {
    SSH2 *ss;
    SV *sv_ss;
    LIBSSH2_KNOWNHOSTS* knownhosts;
} SSH2_KNOWNHOSTS;

#endif

static int net_ss_debug_out = 0;
static unsigned long gensym_count = 0;

/* debug output */
static void debug(const char* format, ...) {
    if (net_ss_debug_out) {
        va_list va;
        va_start(va, format);
        vwarn(format, &va);
        va_end(va);
    }
}

/* libssh2 allocator thunks */
LIBSSH2_ALLOC_FUNC(local_alloc) {
    void *buf;
    New(0, buf, count, char);
    return buf;
}
LIBSSH2_REALLOC_FUNC(local_realloc) {
    return Renew(ptr, count, char);
}
LIBSSH2_FREE_FUNC(local_free) {
    Safefree(ptr);
}

#define SV2TYPE(sv, type) ((type)((sizeof(IV) < sizeof(type)) ? SvNV(sv) : SvIV(sv)))
#define SV2UTYPE(sv, type) ((type)((sizeof(IV) < sizeof(type)) ? SvNV(sv) : SvUV(sv)))

static void
wrap_tied_into(SV *to, const char *pkg, void *object) {
    GV* gv = (GV*)newSVrv(to, pkg);
    IO* io = (IO*)newSV(0);
    SV* name_sv = sv_2mortal(newSVpvf("_GEN_%ld", (long)gensym_count++));
    STRLEN name_len;
    const char *name = SvPVbyte(name_sv, name_len);
        
    SvUPGRADE((SV*)gv, SVt_PVGV);
    gv_init(gv, gv_stashpv(pkg, GV_ADD), name, name_len, 0);
    SvUPGRADE((SV*)io, SVt_PVIO);

    GvSV(gv) = newSViv(PTR2IV(object));
    GvIOp(gv) = io;
#if PERL_VERSION > 6
    sv_magic((SV*)io, newRV((SV*)gv), PERL_MAGIC_tiedscalar, Nullch, 0);
#else
    sv_magic((SV*)gv, newRV((SV*)gv), PERL_MAGIC_tiedscalar, Nullch, 0);
#endif
}

static IV
unwrap(SV *sv, const char *pkg, const char *method) {
    if (SvROK(sv) && sv_isa(sv, pkg)) {
        SV *inner = SvRV(sv);
        if (SvIOK(inner))
            return SvIVX(inner);
    }
    croak("%s::%s: invalid object %s", pkg, method, SvPV_nolen(sv));
}

static IV
unwrap_tied(SV *sv, const char *pkg, const char *method) {
    if (SvROK(sv) && sv_isa(sv, pkg)) {
        SV *gv = SvRV(sv);
        if (SvTYPE(gv) == SVt_PVGV) {
            SV *inner = GvSV((GV*)gv);
            if (inner && SvIOK(inner))
                return SvIVX(inner);
        }
    }
    croak("%s::%s: invalid object %s", pkg, method, SvPV_nolen(sv));
}

/* push a hash of values onto the return stack, for '%hash = func()' */
static int push_hv(SV** sp, HV* hv) {
    I32 keys = hv_iterinit(hv);
    const char* pv_key;
    I32 len_key;
    SV* value;

    EXTEND(SP, keys * 2);
    while ((value = hv_iternextsv(hv, (char**)&pv_key, &len_key))) {
        PUSHs(sv_2mortal(newSVpvn(pv_key, len_key)));
        PUSHs(sv_2mortal(SvREFCNT_inc(value)));
    }
    SvREFCNT_dec(hv);
    return keys * 2;
}

static SV *
sv_upper(SV *sv) {
    STRLEN len, i;
    char *pv = SvPVbyte(sv, len);
    for (i = 0; i < len; i++) {
        if (isLOWER(pv[i])) {
            sv = sv_2mortal(newSVpvn(pv, len));
            pv = SvPVX(sv);
            for (; i < len; i++)
                pv[i] = toUPPER(pv[i]);
            break;
        }
    }
    return sv;
}

static IV
sv2iv_constant_or_croak(const char *name, SV *sv) {
    if (!SvOK(sv) || SvIOK(sv) || looks_like_number(sv))
        return SvIV(sv);
    else {
        STRLEN len;
        char *pv;
        int type, i;
        IV value;
        sv = sv_upper(sv);
        pv = SvPVbyte(sv, len);
        type = constant(aTHX_ pv, len, &value);
        if (type == PERL_constant_NOTFOUND) {
            sv = sv_2mortal(newSVpvf("LIBSSH2_%s_%s", name, pv));
            pv = SvPVbyte(sv, len);
            type = constant(aTHX_ SvPV_nolen(sv), len, &value);
        }
        if (type == PERL_constant_ISIV)
            return value;

        croak("Invalid constant of type LIBSSH2_%s (%s)", name, pv);
    }
}

/* create a hash from an SFTP attributes structure */
static HV*
hv_from_attrs(LIBSSH2_SFTP_ATTRIBUTES* attrs) {
    HV* hv = newHV();
    debug("hv_from_attrs: attrs->flags = %d\n", attrs->flags);
    if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE)
        hv_store(hv, "size", 4, newSVuv(attrs->filesize), 0/*hash*/);
    if (attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID) {
        hv_store(hv, "uid", 3, newSVuv(attrs->uid), 0/*hash*/);
        hv_store(hv, "gid", 3, newSVuv(attrs->gid), 0/*hash*/);
    }
    if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)
        hv_store(hv, "mode", 4, newSVuv(attrs->permissions), 0/*hash*/);
    if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
        hv_store(hv, "atime", 5, newSVuv(attrs->atime), 0/*hash*/);
        hv_store(hv, "mtime", 5, newSVuv(attrs->mtime), 0/*hash*/);
    }
    return hv;
}

/* return attributes from function, as flat hash or hashref */
#define XSRETURN_STAT_ATTRS(name) XSRETURN(return_stat_attrs(sp, &attrs, name))
    
static int return_stat_attrs(SV** sp, LIBSSH2_SFTP_ATTRIBUTES* attrs,
 SV* name) {
    HV* hv_attrs = hv_from_attrs(attrs);
    if (name)
        hv_store(hv_attrs, "name", 4, name, 0/*hash*/);

    switch (GIMME_V) {
    case G_SCALAR:
        PUSHs(sv_2mortal(newRV_noinc((SV*)hv_attrs)));
        return 1;
    case G_ARRAY:
        return push_hv(sp, hv_attrs);
    default:
        SvREFCNT_dec(hv_attrs);
    }
    return 0;
}

/* general wrapper */
#define NEW_ITEM(type, field, create, parent) do { \
    Newz(0/*id*/, RETVAL, 1, type); \
    if (RETVAL) { \
        RETVAL->parent = parent; \
        RETVAL->sv_##parent = SvREFCNT_inc(SvRV(ST(0))); \
        RETVAL->field = create; \
        debug(#create " -> 0x%p\n", RETVAL->field); \
    } \
    if (!RETVAL || !RETVAL->field) { \
        if (RETVAL) \
            SvREFCNT_dec(RETVAL->sv_##parent); \
        Safefree(RETVAL); \
        XSRETURN_EMPTY; \
    } \
} while(0)

/* wrap a libSSH2 channel */
#define NEW_CHANNEL(create) NEW_ITEM(SSH2_CHANNEL, channel, create, ss)

/* wrap a libSSH2 listener */
#define NEW_LISTENER(create) NEW_ITEM(SSH2_LISTENER, listener, create, ss)

/* wrap a libSSH2 SFTP connection */
#define NEW_SFTP(create) NEW_ITEM(SSH2_SFTP, sftp, create, ss)

/* wrap a libSSH2 SFTP file */
#define NEW_FILE(create) NEW_ITEM(SSH2_FILE, handle, create, sf)

/* wrap a libSSH2 SFTP directory */
#define NEW_DIR(create) NEW_ITEM(SSH2_DIR, handle, create, sf)

/* wrap a libSSH2 public key object */
#define NEW_PUBLICKEY(create) NEW_ITEM(SSH2_PUBLICKEY, pkey, create, ss)

/* wrap a libSSH2 knownhosts object */
#define NEW_KNOWNHOSTS(create) NEW_ITEM(SSH2_KNOWNHOSTS, knownhosts, create, ss)

static void
set_cb_args(pTHX_ AV* data) {
    GV *gv = gv_fetchpv("Net::SSH2::_cb_args", 1, SVt_PV);
    SV *sv = save_scalar(gv);
    sv_setsv(sv, sv_2mortal(newRV_inc((SV*)data)));
}

static SV*
get_cb_arg(pTHX_ I32 ix) {
    SV *sv = get_sv("Net::SSH2::_cb_args", 1);
    if (SvROK(sv)) {
        AV *data = (AV*)SvRV(sv);
        if (SvTYPE(data) == SVt_PVAV) {
            SV **svp = av_fetch(data, ix, 0);
            if (svp && *svp)
                return *svp;
            Perl_croak(aTHX_ "internal error: unable to fetch callback data slot %d", ix);
        }
    }
    Perl_croak(aTHX_ "internal error: unexpected structure found for callback data");
}

/* callback for returning a password via "keyboard-interactive" auth */
static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(cb_kbdint_response_password) {
    if (num_prompts != 1 || prompts[0].echo) {
        int i;
        for (i = 0; i < num_prompts; ++i) {
            responses[i].text = NULL;
            responses[i].length = 0;
        }
    }
    else {
        /* single prompt, no echo: assume it's a password request */
        dTHX;
        SV *password = get_cb_arg(aTHX_ 0);
        STRLEN len_password;
        const char* pv_password = SvPVbyte(password, len_password);

        responses[0].text = savepvn(pv_password, len_password);
        responses[0].length = len_password;
    }
}

/* thunk to call perl input-reading function for "keyboard-interactive" auth */
static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(cb_kbdint_response_callback) {
    dTHX; dSP;
    int count, i;
    SV *cb = get_cb_arg(aTHX_ 0);
    SV *self = get_cb_arg(aTHX_ 1);
    SV *username = get_cb_arg(aTHX_ 2);

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    EXTEND(SP, 4 + num_prompts);
    PUSHs(self);
    PUSHs(username);
    PUSHs(sv_2mortal(newSVpvn(name, name_len)));
    PUSHs(sv_2mortal(newSVpvn(instruction, instruction_len)));
    for (i = 0; i < num_prompts; ++i) {
        HV* hv = newHV();
        /* Perl_warn(aTHX_ "prompt %d: text: %p, length: %d, echo: %d\n", */
        /* i, prompts[i].text, prompts[i].length, prompts[i].echo); */
        PUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
        hv_store(hv, "text", 4, newSVpvn(prompts[i].text, prompts[i].length), 0);
        hv_store(hv, "echo", 4, newSVuv(prompts[i].echo), 0);
        responses[i].text = NULL;
        responses[i].length = 0;
    }
    PUTBACK;
    count = call_sv(cb, G_ARRAY);
    SPAGAIN;
    if (count > num_prompts) {
        Perl_warn(aTHX_ "Too many responses from callback, %d expected but %d found!",
                  num_prompts, count);
        while (count-- > num_prompts)
            POPs;
    }
    while (count-- > 0) {
        STRLEN len_response;
        SV *sv = POPs;
        char *pv_response = SvPVbyte(sv, len_response);
        responses[count].text = savepvn(pv_response, len_response);
        responses[count].length = len_response;
    }
    PUTBACK;
    FREETMPS;
    LEAVE;
}

/* thunk to call perl password change function for "password" auth */
static LIBSSH2_PASSWD_CHANGEREQ_FUNC(cb_password_change_callback) {
    dTHX; dSP;
    int count;
    SV *cb = get_cb_arg(aTHX_ 0);
    SV *self = get_cb_arg(aTHX_ 1);
    SV *username = get_cb_arg(aTHX_ 2);

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(self);
    XPUSHs(username);
    PUTBACK;
    count = call_sv(cb, G_SCALAR);
    SPAGAIN;
    if (count > 0) {
        STRLEN len_password;
        const char* pv_password = SvPVbyte(POPs, len_password);
        *newpw = savepvn(pv_password, len_password);
        *newpw_len = len_password;
    }
    else {
        *newpw = NULL;
        *newpw_len = 0;
    }
    PUTBACK;
    FREETMPS;
    LEAVE;
}

/* thunk to call perl SSH_MSG_IGNORE packet function */
static LIBSSH2_IGNORE_FUNC(cb_ignore_callback) {
    SSH2* ss = (SSH2*)*abstract;

    dSP; I32 ax; int count;
    ENTER; SAVETMPS; PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc(ss->sv_ss)));
    mXPUSHp(message, message_len);
    PUTBACK;

    count = call_sv(ss->rgsv_cb[LIBSSH2_CALLBACK_IGNORE], G_VOID);
    SPAGAIN; SP -= count; ax = (SP - PL_stack_base) + 1;

    PUTBACK; FREETMPS; LEAVE;
}

/* thunk to call perl SSH_MSG_DEBUG packet function */
static LIBSSH2_DEBUG_FUNC(cb_debug_callback) {
    SSH2* ss = (SSH2*)*abstract;

    dSP; I32 ax; int count;
    ENTER; SAVETMPS; PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc(ss->sv_ss)));
    mXPUSHi(always_display);
    mXPUSHp(message, message_len);
    mXPUSHp(language, language_len);
    PUTBACK;

    count = call_sv(ss->rgsv_cb[LIBSSH2_CALLBACK_DEBUG], G_VOID);
    SPAGAIN; SP -= count; ax = (SP - PL_stack_base) + 1;

    PUTBACK; FREETMPS; LEAVE;
}

/* thunk to call perl SSH_MSG_DISCONNECT packet function */
static LIBSSH2_DISCONNECT_FUNC(cb_disconnect_callback) {
    SSH2* ss = (SSH2*)*abstract;

    dSP; I32 ax; int count;
    ENTER; SAVETMPS; PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc(ss->sv_ss)));
    mXPUSHi(reason);
    mXPUSHp(message, message_len);
    mXPUSHp(language, language_len);
    PUTBACK;

    count = call_sv(ss->rgsv_cb[LIBSSH2_CALLBACK_DISCONNECT], G_VOID);
    SPAGAIN; SP -= count; ax = (SP - PL_stack_base) + 1;

    PUTBACK; FREETMPS; LEAVE;
}

/* thunk to call perl SSH_MSG_MACERROR packet function */
static LIBSSH2_MACERROR_FUNC(cb_macerror_callback) {
    SSH2* ss = (SSH2*)*abstract;
    int ret = 0;

    dSP; I32 ax; int count;
    ENTER; SAVETMPS; PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc(ss->sv_ss)));
    mXPUSHp(packet, packet_len);
    PUTBACK;

    count = call_sv(ss->rgsv_cb[LIBSSH2_CALLBACK_MACERROR], G_SCALAR);
    SPAGAIN; SP -= count ; ax = (SP - PL_stack_base) + 1;

    if (count > 0)
        ret = SvIV(ST(0));
 
    PUTBACK; FREETMPS; LEAVE;
    return ret;
}

/* thunk to call perl X11 forwarder packet function */
static LIBSSH2_X11_OPEN_FUNC(cb_x11_open_callback) {
    SSH2* ss = (SSH2*)*abstract;

    dSP; I32 ax; int count;
    ENTER; SAVETMPS; PUSHMARK(SP);
    XPUSHs(sv_2mortal(newRV_inc(ss->sv_ss)));
    /*TODO: we actually need to push a channel here, but we don't know the
     *      SV of the channel (use a local hash?) */
    XPUSHs(&PL_sv_undef);
    mXPUSHp(shost, strlen(shost));
    mXPUSHi(sport);
    PUTBACK;

    count = call_sv(ss->rgsv_cb[LIBSSH2_CALLBACK_X11], G_VOID);
    SPAGAIN; SP -= count ; ax = (SP - PL_stack_base) + 1 ;

    PUTBACK; FREETMPS; LEAVE;
}

void * cb_as_void_ptr(void (*cb)()) {
    void * addr;
    memcpy(&addr, &cb, sizeof addr);
    return addr;
}

static void (*msg_cb[])() = {
    (void (*)())cb_ignore_callback,
    (void (*)())cb_debug_callback,
    (void (*)())cb_disconnect_callback,
    (void (*)())cb_macerror_callback,
    (void (*)())cb_x11_open_callback
};

#define MY_CXT_KEY "Net::SSH2::_guts" XS_VERSION

#ifdef HAVE_GCRYPT
#ifndef WIN32
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#else
GCRY_THREAD_OPTION_PTH_IMPL;
#endif
#endif

typedef struct {
    HV* global_cb_data;
    UV tid;
} my_cxt_t;

START_MY_CXT

static UV get_my_thread_id(void) /* returns threads->tid() value */
{
    dSP;
    UV tid = 0;
    int count = 0;

#ifdef USE_ITHREADS
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVpv("threads", 0)));
    PUTBACK;
    count = call_method("tid", G_SCALAR|G_EVAL);
    SPAGAIN;
    if (SvTRUE(ERRSV) || count != 1)
       /* if threads not loaded or an error occurs return 0 */
       tid = 0;
    else
       tid = (UV)POPi;
    PUTBACK;
    FREETMPS;
    LEAVE;
#endif

    return tid;
}

#if defined(USE_ITHREADS) && !defined(HAVE_GCRYPT)
/* IMPORTANT NOTE:
 * openssl locking was implemented according to http://www.openssl.org/docs/crypto/threads.html
 * we implement both static and dynamic locking as described on URL above
 * locking is supported when OPENSSL_THREADS macro is defined which means openssl-0.9.7 or newer
 * we intentionally do not implement cleanup of openssl's threading as it causes troubles
 * with apache-mpm-worker+mod_perl+mod_ssl+net-ssleay
 */

static perl_mutex *GLOBAL_openssl_mutex = NULL;

static void openssl_locking_function(int mode, int type, const char *file, int line)
{
    if (!GLOBAL_openssl_mutex) return;
    if (mode & CRYPTO_LOCK)
      MUTEX_LOCK(&GLOBAL_openssl_mutex[type]);
    else
      MUTEX_UNLOCK(&GLOBAL_openssl_mutex[type]);
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
static unsigned long openssl_threadid_func(void)
{
    dMY_CXT;
    return (unsigned long)(MY_CXT.tid);
}
#else
static void openssl_threadid_func(CRYPTO_THREADID *id)
{
    dMY_CXT;
    CRYPTO_THREADID_set_numeric(id, (unsigned long)(MY_CXT.tid));
}
#endif

struct CRYPTO_dynlock_value
{
    perl_mutex mutex;
};

static struct CRYPTO_dynlock_value *openssl_dynlocking_create_function(const char *file, int line)
{
    struct CRYPTO_dynlock_value *retval;
    New(0, retval, 1, struct CRYPTO_dynlock_value);
    if (!retval) return NULL;
    MUTEX_INIT(&retval->mutex);
    return retval;
}

static void openssl_dynlocking_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
    if (!l) return;
    if (mode & CRYPTO_LOCK)
      MUTEX_LOCK(&l->mutex);
    else
      MUTEX_UNLOCK(&l->mutex);
}

static void openssl_dynlocking_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
    if (!l) return;
    MUTEX_DESTROY(&l->mutex);
    Safefree(l);
}

static void openssl_threads_init(void)
{
    int i;

    /* initialize static locking */
    if ( !CRYPTO_get_locking_callback() ) {
#if OPENSSL_VERSION_NUMBER < 0x10000000L
        if ( !CRYPTO_get_id_callback() ) {
#else
        if ( !CRYPTO_THREADID_get_callback() ) {
#endif
            New(0, GLOBAL_openssl_mutex, CRYPTO_num_locks(), perl_mutex);
            if (!GLOBAL_openssl_mutex) return;
            for (i=0; i<CRYPTO_num_locks(); i++) MUTEX_INIT(&GLOBAL_openssl_mutex[i]);
            CRYPTO_set_locking_callback(openssl_locking_function);

#ifndef WIN32
            /* no need for threadid_func() on Win32 */
#if OPENSSL_VERSION_NUMBER < 0x10000000L
            CRYPTO_set_id_callback(openssl_threadid_func);
#else
            CRYPTO_THREADID_set_callback(openssl_threadid_func);
#endif
#endif
        }
    }

    /* initialize dynamic locking */
    if ( !CRYPTO_get_dynlock_create_callback() &&
         !CRYPTO_get_dynlock_lock_callback() &&
         !CRYPTO_get_dynlock_destroy_callback() ) {
        CRYPTO_set_dynlock_create_callback(openssl_dynlocking_create_function);
        CRYPTO_set_dynlock_lock_callback(openssl_dynlocking_lock_function);
        CRYPTO_set_dynlock_destroy_callback(openssl_dynlocking_destroy_function);
    }
}

#else

/* no threads */
static void openssl_threads_init(void)
{
}

#endif

static void
croak_last_error(SSH2 *ss, const char *class, const char *method) {
    char *errmsg = NULL;
    int err = libssh2_session_last_error(ss->session, &errmsg, NULL, 0);
    croak("%s::%s: %s (%d)", class, method, errmsg, err);
}

#define CROAK_LAST_ERROR(session, method) (croak_last_error((session), class, (method)))

#if LIBSSH2_VERSION_NUM < 0x010601
#define libssh2_session_set_last_error(ss, errcode, errmsg)   0
#endif

static void
save_eagain(LIBSSH2_SESSION *session, int error) {
    if (error == LIBSSH2_ERROR_EAGAIN)
        libssh2_session_set_last_error(session, LIBSSH2_ERROR_EAGAIN, "Operation would block");
}

/* perl module exports */

MODULE = Net::SSH2		PACKAGE = Net::SSH2		PREFIX = net_ss_
PROTOTYPES: DISABLE

INCLUDE: const-xs.inc

BOOT:
{
    MY_CXT_INIT;
#ifdef HAVE_GCRYPT
    gcry_error_t ret;
#ifndef WIN32
    ret = gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#else
    ret = gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pth);
#endif
    if (gcry_err_code(ret) != GPG_ERR_NO_ERROR)
        croak("could not initialize libgcrypt for threads (%d: %s/%s)",
         gcry_err_code(ret),
         gcry_strsource(ret),
         gcry_strerror(ret));

    if (!gcry_check_version(GCRYPT_VERSION))
        croak("libgcrypt version mismatch (needed: %s)", GCRYPT_VERSION);
#else /* OpenSSL */
    openssl_threads_init();
    MY_CXT.global_cb_data = newHV();
    MY_CXT.tid = get_my_thread_id();
    debug("Net::SSH2::BOOT: tid=%d my_perl=0x%p\n", MY_CXT.tid, my_perl);
#endif
}

#define class "Net::SSH2"

void
CLONE(...)
CODE:
    MY_CXT_CLONE;
    MY_CXT.global_cb_data = newHV();
    MY_CXT.tid = get_my_thread_id();
    debug("%s::CLONE: tid=%d my_perl=0x%p\n", class, MY_CXT.tid, my_perl);

IV
_parse_constant(char *prefix, SV *value)
CODE:
    RETVAL = sv2iv_constant_or_croak(prefix, value);
OUTPUT:
    RETVAL

SSH2*
net_ss__new(SV* proto)
CODE:
    Newz(0/*id*/, RETVAL, 1, SSH2);
    if (RETVAL) {
        RETVAL->session = libssh2_session_init_ex(
         local_alloc, local_free, local_realloc, RETVAL);
    }
    if (!RETVAL || !RETVAL->session) {
        Safefree(RETVAL);
        XSRETURN_EMPTY;
    }
    debug("Net::SSH2: created new object 0x%x\n", RETVAL);
OUTPUT:
    RETVAL

void
net_ss_trace(SSH2* ss, IV bitmask)
CODE:
    libssh2_trace(ss->session, bitmask);

#if LIBSSH2_VERSION_MAJOR >= 1

IV
net_ss_block_directions(SSH2* ss)
CODE:
    RETVAL = libssh2_session_block_directions(ss->session);
OUTPUT:
    RETVAL

#else

void
net_ss_block_directions(SSH2* ss)
CODE:
    croak("libssh2 version 1.0 or higher required for block_directions support");

#endif

#if LIBSSH2_VERSION_NUM >= 0x010209

SV *
net_ss_timeout(SSH2* ss, SV *timeout = &PL_sv_undef)
PREINIT:
    long r;
CODE:
    if (items > 1)
        libssh2_session_set_timeout(ss->session,
                                    (SvOK(timeout) ? SvUV(timeout) : 0));
    r = libssh2_session_get_timeout(ss->session);
    RETVAL = (r > 0 ? newSVuv(r) : &PL_sv_undef);
OUTPUT:
    RETVAL

#else

void
net_ss_timeout(SSH2* ss, long timeout)
CODE:
    croak("libssh2 version 1.2.9 or higher required for set_timeout support");

#endif

SSH2_BOOL
net_ss_blocking(SSH2* ss, SSH2_BOOL blocking = 0)
CODE:
    if (items > 1)
        libssh2_session_set_blocking(ss->session, blocking);
    RETVAL = libssh2_session_get_blocking(ss->session);
OUTPUT:
    RETVAL

void
net_ss_DESTROY(SSH2* ss)
CODE:
    debug("%s::DESTROY object 0x%x\n", class, ss);
    libssh2_session_free(ss->session);
    if (ss->socket)
        SvREFCNT_dec(ss->socket);
    if (ss->hostname)
        SvREFCNT_dec(ss->hostname);
    Safefree(ss);

void
net_ss_debug(SV*, IV debug)
CODE:
    net_ss_debug_out = debug & 1;  /* allow for future flags */

void
net_ss_version(...)
PPCODE:
    EXTEND(SP, 3);
    ST(0) = sv_2mortal(newSVpv(LIBSSH2_VERSION, 0));
    if (GIMME_V != G_ARRAY)
        XSRETURN(1);
#ifdef LIBSSH2_VERSION_NUM
    ST(1) = sv_2mortal(newSVuv(LIBSSH2_VERSION_NUM));
#else
    ST(1) = &PL_sv_undef;
#endif
    ST(2) = sv_2mortal(newSVpv(LIBSSH2_SSH_DEFAULT_BANNER, 0));
    XSRETURN(3);

SSH2_NERROR
net_ss_banner(SSH2* ss, SSH2_CHARP banner)
PREINIT:
    SV* full_banner;
CODE:
    full_banner = sv_2mortal(newSVpvf("SSH-2.0-%s", banner));
    RETVAL = libssh2_banner_set(ss->session, SvPVbyte_nolen(full_banner));
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_ERROR
net_ss_error(SSH2* ss)
PREINIT:
    char* errstr;
    int errlen;
CODE:
    RETVAL = libssh2_session_last_error(ss->session, &errstr, &errlen, 0);
    if(GIMME_V == G_ARRAY) {
        SV *errcode_sv;
        if (RETVAL == LIBSSH2_ERROR_NONE)
            XSRETURN_EMPTY;
        EXTEND(SP, 3);
        ST(0) = sv_2mortal(newSViv(RETVAL));
        if ((-RETVAL > 0) && (-RETVAL < countof(xs_libssh2_error)))
            errcode_sv = newSVpvf("LIBSSH2_ERROR_%s", xs_libssh2_error[-RETVAL]);
        else
            errcode_sv = newSVpvf("LIBSSH2_ERROR_UNKNOWN(%d)", RETVAL);
        ST(1) = sv_2mortal(errcode_sv);
        ST(2) = (errstr ? sv_2mortal(newSVpvn(errstr, errlen)) : &PL_sv_undef);
        XSRETURN(3);
    }
OUTPUT:
    RETVAL

void
net_ss__set_error(SSH2 *ss, int errcode = 0, SSH2_CHARP_OR_NULL errmsg = NULL)
CODE:
    libssh2_session_set_last_error(ss->session, errcode, errmsg);

SSH2_NERROR
net_ss__method(SSH2* ss, SSH2_METHOD type, SSH2_CHARP_OR_NULL prefs = NULL)
CODE:
    /* if there are no other parameters, return the current value */
    if (items == 2) {
        const char *method = libssh2_session_methods(ss->session, (int)type);
        if (!method)
            XSRETURN_EMPTY;
        XSRETURN_PV(method);
    }
    RETVAL = libssh2_session_method_pref(ss->session,
                                         (int)type, prefs);
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x010200

SSH2_NERROR
net_ss_flag(SSH2* ss, SSH2_FLAG flag, int value)
CODE:
    RETVAL = libssh2_session_flag(ss->session, (int)flag, value);
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

#else

void
net_ss_flag(SSH2* ss, SV* flag, int value)
CODE:
    croak("libssh2 version 1.2 or higher required for flag support");

#endif

SSH2_RC
net_ss_callback(SSH2* ss, SSH2_CALLBACK type, SV* callback = NULL)
CODE:
    if (callback && !SvOK(callback))
        callback = NULL;
    if (callback && !(SvROK(callback) && SvTYPE(SvRV(callback)) == SVt_PVCV))
        croak("%s::callback: callback must be CODE ref", class);
    if (type < 0 || type >= countof(msg_cb))
        croak("%s::callback: don't know how to handle: %s",
              class, SvPVbyte_nolen(callback));

    ss->sv_ss = SvRV(ST(0));  /* don't keep a reference, just store it */
    SvREFCNT_dec(ss->rgsv_cb[type]);
    libssh2_session_callback_set(ss->session,
     type, callback ? cb_as_void_ptr(msg_cb[type]) : NULL);
    SvREFCNT_inc(callback);
    ss->rgsv_cb[type] = callback;
    RETVAL = 1;
OUTPUT:
    RETVAL

SSH2_NERROR
net_ss__startup(SSH2* ss, int fd, SV *socket, SV* hostname, int port)
CODE:
    RETVAL = libssh2_session_startup(ss->session, fd);
    if ((RETVAL >= 0) && SvOK(socket)) {
        if (ss->socket)
            sv_2mortal(ss->socket);
        ss->socket = newSVsv(socket);
        ss->hostname = newSVsv(hostname);
        ss->port = port;
    }
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

SV *
net_ss_hostname(SSH2* ss)
CODE:
    RETVAL = (ss->hostname ? newSVsv(ss->hostname) : &PL_sv_undef);
OUTPUT:
    RETVAL

int
net_ss_port(SSH2* ss)
CODE:
    RETVAL = ss->port;
 OUTPUT:
    RETVAL

SV *
net_ss_sock(SSH2* ss)
CODE:
    RETVAL = (ss->socket ? newSVsv(ss->socket) : &PL_sv_undef);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ss_disconnect(SSH2* ss, SSH2_CHARP description = "",       \
                  int reason = SSH_DISCONNECT_BY_APPLICATION, SSH2_CHARP lang = "")
CODE:
    RETVAL = libssh2_session_disconnect_ex(ss->session, reason, description, lang);
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

void
net_ss_hostkey_hash(SSH2* ss, SSH2_HOSTKEY_HASH type)
PREINIT:
    const char* hash;
    static STRLEN rglen[] = { 16/*MD5*/, 20/*SHA1*/ };
PPCODE:
    if (type < 1 || type > countof(rglen)) {
        croak("%s::hostkey: unknown hostkey hash: %d",
              class, (int)type);
    }
    if ((hash = (const char*)libssh2_hostkey_hash(ss->session, type))) {
        PUSHs(sv_2mortal(newSVpvn(hash, rglen[type-1])));
        XSRETURN(1);
    }
    XSRETURN_EMPTY;

void
net_ss_remote_hostkey(SSH2* ss)
PREINIT:
    const char *key_pv;
    size_t key_len;
    int type_int;
PPCODE:
    if ((key_pv = libssh2_session_hostkey(ss->session, &key_len, &type_int))) {
        XPUSHs(sv_2mortal(newSVpvn(key_pv, key_len)));
        if (GIMME_V != G_ARRAY)
            XSRETURN(1);
        else {
            XPUSHs(sv_2mortal(newSViv(type_int)));
            XSRETURN(2);
        }
    }
    else
        XSRETURN_EMPTY;

SSH2_CHARP_OR_NULL
net_ss__auth_list(SSH2* ss, SV *username = &PL_sv_undef)
PREINIT:
    const char* pv_username = NULL;
    STRLEN len_username = 0;
CODE:
    if (SvOK(username))
        pv_username = SvPVbyte(username, len_username);
    RETVAL = libssh2_userauth_list(ss->session, pv_username, len_username);
OUTPUT:
    RETVAL

SSH2_RC
net_ss_auth_ok(SSH2* ss)
CODE:
    RETVAL = libssh2_userauth_authenticated(ss->session);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ss_auth_password(SSH2* ss,                                  \
                     SV* username, SV* password = &PL_sv_undef, \
                     SV* callback = &PL_sv_undef)
PREINIT:
    STRLEN len_username, len_password;
    const char *pv_username, *pv_password;
    int i, ok;
CODE:
    pv_username = SvPVbyte(username, len_username);

    /* if we don't have a password, try for an unauthenticated login */
    if (!SvPOK(password)) {
        /* That's how libssh2 tells you authentication 'none' is valid */
        RETVAL = (((libssh2_userauth_list(ss->session, pv_username, len_username) == NULL) &&
                   libssh2_userauth_authenticated(ss->session)) ? 0 : -1);
    }
    else {
        if (SvOK(callback)) {
            if (!(SvROK(callback) && SvTYPE(SvRV(callback)) == SVt_PVCV))
                Perl_croak(aTHX_ "%s::auth_password: callback must be CODE ref", class);
            else {
                AV *cb_args = (AV*)sv_2mortal((SV*)newAV());
                av_push(cb_args, newSVsv(callback));
                av_push(cb_args, newSVsv(ST(0))); /*session */
                av_push(cb_args, newSVsv(username));
                set_cb_args(aTHX_ cb_args);
            }
        }

        pv_password = SvPVbyte(password, len_password);
        RETVAL = libssh2_userauth_password_ex(ss->session,
                                              pv_username, len_username,
                                              pv_password, len_password,
                                              (SvOK(callback) ? cb_password_change_callback : NULL));
        save_eagain(ss->session, RETVAL);
    }
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x010203

SV *
net_ss_auth_agent(SSH2* ss, SSH2_CHARP username)
PREINIT:
    LIBSSH2_AGENT *agent;
    int old_blocking;
CODE:
    RETVAL = &PL_sv_undef;
    /* unfortunatelly this can't be make to work on nb mode */
    old_blocking = libssh2_session_get_blocking(ss->session);
    libssh2_session_set_blocking(ss->session, 1);
    if ((agent = libssh2_agent_init(ss->session)) != NULL) {
        if (libssh2_agent_connect(agent) == LIBSSH2_ERROR_NONE) {
            if (libssh2_agent_list_identities(agent) == LIBSSH2_ERROR_NONE) {
                struct libssh2_agent_publickey *identity = NULL;
                while (libssh2_agent_get_identity(agent, &identity, identity) == 0) {
                    if (libssh2_agent_userauth(agent, username, identity) == LIBSSH2_ERROR_NONE) {
                        RETVAL = &PL_sv_yes;
                        break;
                    }
                }
            }
        }
        libssh2_agent_free(agent);
    }
    libssh2_session_set_blocking(ss->session, old_blocking);
OUTPUT:
    RETVAL

#else

void
net_ss_auth_agent(SSH2* ss, SV* username)
CODE:
    croak("libssh2 version 1.2.3 or higher required for agent support");

#endif

SSH2_NERROR
net_ss_auth_publickey(SSH2* ss, SV* username, SSH2_CHARP_OR_NULL publickey, \
                      SSH2_CHARP privatekey, SSH2_CHARP_OR_NULL passphrase = NULL);
PREINIT:
    const char* pv_username;
    STRLEN len_username;
CODE:
    pv_username = SvPVbyte(username, len_username);
    RETVAL = libssh2_userauth_publickey_fromfile_ex(ss->session,
                                                    pv_username, len_username,
                                                    publickey, privatekey,
                                                    passphrase);
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x010600

SSH2_NERROR
net_ss_auth_publickey_frommemory(SSH2* ss, SV* username, SV* publickey, \
                                 SV* privatekey, SSH2_CHARP_OR_NULL passphrase = NULL)
PREINIT:
    const char *pv_username, *pv_publickey, *pv_privatekey;
    STRLEN len_username, len_publickey, len_privatekey;
CODE:
    pv_username = SvPVbyte(username, len_username);
    pv_publickey = SvPVbyte(publickey, len_publickey);
    pv_privatekey = SvPVbyte(privatekey, len_privatekey);

    RETVAL = libssh2_userauth_publickey_frommemory(ss->session,
                                                   pv_username, len_username, pv_publickey, len_publickey,
                                                   pv_privatekey, len_privatekey,
                                                   passphrase);
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

#endif

SSH2_NERROR
net_ss_auth_hostbased(SSH2* ss, SV* username, const char* publickey, \
                      const char* privatekey, SV* hostname,          \
                      SV* local_username = &PL_sv_undef,             \
                      SSH2_CHARP_OR_NULL passphrase = NULL)
PREINIT:
    const char* pv_username, * pv_hostname, * pv_local_username;
    STRLEN len_username, len_hostname, len_local_username;
CODE:
    pv_username = SvPVbyte(username, len_username);
    pv_hostname = SvPVbyte(hostname, len_hostname);

    if (SvPOK(local_username)) {
        pv_local_username = SvPVbyte(local_username, len_local_username);
    }
    else {
        pv_local_username = pv_username;
        len_local_username = len_username;
    }
    RETVAL = libssh2_userauth_hostbased_fromfile_ex(ss->session,
                                                    pv_username, len_username, publickey, privatekey,
                                                    passphrase,
                                                    pv_hostname, len_hostname,
                                                    pv_local_username, len_local_username);
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ss_auth_keyboard(SSH2* ss, SV* username, SV* password = NULL)
PREINIT:
    const char* pv_username;
    STRLEN len_username;
    AV *cb_args;
CODE:
    pv_username = SvPVbyte(username, len_username);

    /* we either have a password, or a reference to a callback */

    if (!password || !SvOK(password)) {
        password = sv_2mortal(newRV_inc((SV*)get_cv("Net::SSH2::_cb_kbdint_response_default", 1)));
        if (!SvOK(password))
            Perl_croak(aTHX_ "Internal error: unable to retrieve callback");
    }

    cb_args = (AV*)sv_2mortal((SV*)newAV());
    av_push(cb_args, newSVsv(password));
    av_push(cb_args, newSVsv(ST(0))); /*session */
    av_push(cb_args, newSVsv(username));
    set_cb_args(aTHX_ cb_args);

    if (SvROK(password) && (SvTYPE(SvRV(password)) == SVt_PVCV))
        RETVAL = libssh2_userauth_keyboard_interactive_ex(ss->session,
                                                          pv_username, len_username,
                                                          cb_kbdint_response_callback);
    else
        RETVAL = libssh2_userauth_keyboard_interactive_ex(ss->session,
                                                          pv_username, len_username,
                                                          cb_kbdint_response_password);
    save_eagain(ss->session, RETVAL);
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x010205

void
net_ss_keepalive_config(SSH2 *ss, int want_reply, unsigned int interval)
CODE:
    libssh2_keepalive_config(ss->session, want_reply, interval);

SSH2_BYTES
net_ss_keepalive_send(SSH2 *ss)
PREINIT:
    int seconds_to_next;
CODE:
    RETVAL = libssh2_keepalive_send(ss->session, &seconds_to_next);
    save_eagain(ss->session, RETVAL);
    if (RETVAL >= 0) RETVAL = seconds_to_next;
OUTPUT:
    RETVAL

#else

void
net_ss_keepalive_config(SSH2 *ss, int want_reply, unsigned int interval)
CODE:
    croak("libssh2 version 1.2.5 or higher required for keepalive_config support");

void
net_ss_keepalive_send(SSH2 *ss)
CODE:
    croak("libssh2 version 1.2.5 or higher required for keepalive_send support");

#endif

SSH2_CHANNEL*
net_ss_channel(SSH2* ss,  SSH2_CHARP_OR_NULL channel_type = NULL,   \
               int window_size = LIBSSH2_CHANNEL_WINDOW_DEFAULT,    \
               int packet_size = LIBSSH2_CHANNEL_PACKET_DEFAULT)
PREINIT:
    static const char mandatory_type[] = "session";
CODE:
    if (channel_type && strcmp(channel_type, mandatory_type))
        Perl_croak(aTHX_ "channel_type must be 'session' ('%s' given)", channel_type);
    NEW_CHANNEL(libssh2_channel_open_ex(ss->session,
        mandatory_type, strlen(mandatory_type), window_size, packet_size,
        NULL/*message*/, 0/*message_len*/));
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x10601

SSH2_CHANNEL*
net_ss__scp_get(SSH2* ss, SSH2_CHARP path, HV* stat)
PREINIT:
    libssh2_struct_stat st;
CODE:
    NEW_CHANNEL(libssh2_scp_recv2(ss->session, path, &st));
    hv_store(stat, "mode",  4, newSVuv(st.st_mode),  0/*hash*/);
    hv_store(stat, "uid",   3, newSVuv(st.st_uid),   0/*hash*/);
    hv_store(stat, "gid",   3, newSVuv(st.st_gid),   0/*hash*/);
#if IVSIZE >= 8
    hv_store(stat, "size",  4, newSVuv(st.st_size),  0/*hash*/);
#else
    hv_store(stat, "size",  4, newSVnv(st.st_size),  0/*hash*/);
#endif
    hv_store(stat, "atime", 5, newSVuv((time_t)st.st_atime), 0/*hash*/);
    hv_store(stat, "mtime", 5, newSVuv((time_t)st.st_mtime), 0/*hash*/);
OUTPUT:
    RETVAL

#else

SSH2_CHANNEL*
net_ss__scp_get(SSH2* ss, SSH2_CHARP path, HV* stat)
PREINIT:
    struct stat st;
CODE:
    NEW_CHANNEL(libssh2_scp_recv(ss->session, path, &st));
    hv_store(stat, "mode",  4, newSVuv(st.st_mode),  0/*hash*/);
    hv_store(stat, "uid",   3, newSVuv(st.st_uid),   0/*hash*/);
    hv_store(stat, "gid",   3, newSVuv(st.st_gid),   0/*hash*/);
    hv_store(stat, "size",  4, newSVuv(st.st_size),  0/*hash*/);
    hv_store(stat, "atime", 5, newSVuv((time_t)st.st_atime), 0/*hash*/);
    hv_store(stat, "mtime", 5, newSVuv((time_t)st.st_mtime), 0/*hash*/);
OUTPUT:
    RETVAL

#endif

#if LIBSSH2_VERSION_NUM >= 0x10206

SSH2_CHANNEL*
net_ss__scp_put(SSH2* ss, SSH2_CHARP path, int mode, SSH2_BYTESU64 size, \
                time_t mtime = 0, time_t atime = 0)
CODE:
    NEW_CHANNEL(libssh2_scp_send64(ss->session,
                                   path, mode, size, mtime, atime));
OUTPUT:
    RETVAL

#else
SSH2_CHANNEL*
net_ss__scp_put(SSH2* ss, SSH2_CHARP path, int mode, size_t size, \
                long mtime = 0, long atime = 0)
CODE:
    NEW_CHANNEL(libssh2_scp_send_ex(ss->session,
                                    path, mode, size, mtime, atime));
OUTPUT:
    RETVAL

#endif

SSH2_CHANNEL*
net_ss_tcpip(SSH2* ss, SSH2_CHARP host, int port, \
             SSH2_CHARP shost = "127.0.0.1", int sport = 22)
CODE:
    NEW_CHANNEL(libssh2_channel_direct_tcpip_ex(ss->session,
                                                (char*)host, port,
                                                (char*)shost, sport));
OUTPUT:
    RETVAL

SSH2_LISTENER*
net_ss_listen(SSH2* ss, int port, const char* host = NULL, \
              SV* bound_port = NULL, int queue_maxsize = 16)
PREINIT:
    int i_bound_port;
CODE:
    if (bound_port && SvOK(bound_port)) {
        if (!SvROK(bound_port) && SvTYPE(SvRV(bound_port)) <= SVt_PVNV)
            croak("%s::listen: bound port must be scalar reference", class);
    } else
        bound_port = NULL;
    NEW_LISTENER(libssh2_channel_forward_listen_ex(ss->session,
     (char*)host, port, bound_port ? &i_bound_port : NULL, queue_maxsize));
    if (RETVAL && bound_port)
        sv_setiv(SvRV(bound_port), i_bound_port);
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x010200

SSH2_KNOWNHOSTS*
net_ss_known_hosts(SSH2 *ss)
CODE:
    NEW_KNOWNHOSTS(libssh2_knownhost_init(ss->session));
OUTPUT:
    RETVAL

#else

void
net_ss_known_hosts(SSH2 *ss)
CODE:
    croak("libssh2 version 1.2 or higher required for known_hosts support");

#endif

void
net_ss__poll(SSH2* ss, int timeout, AV* event)
PREINIT:
    LIBSSH2_POLLFD* pollfd;
    int i, count, changed;
CODE:
    count = av_len(event) + 1;
    debug("%s::poll: timeout = %d, array[%d]\n", class, timeout, count);
    if (!count)  /* some architectures return null for malloc(0) */
        XSRETURN_IV(0);

    New(0, pollfd, count, LIBSSH2_POLLFD);
    if (!pollfd)
        Perl_croak(aTHX_ "Out of memory!");

    for (i = 0; i < count; ++i) {
        SV* sv = *av_fetch(event, i, 0/*lval*/), ** handle, ** events;
        HV* hv;

        if (!SvROK(sv) || SvTYPE(SvRV(sv)) != SVt_PVHV)
            croak("%s::poll: array element %d is not hash", class, i);
        hv = (HV*)SvRV(sv);

        if (!(handle = hv_fetch(hv, "handle", 6, 0/*lval*/)) || !*handle)
            croak("%s::poll: array element %d missing handle", class, i);
        if (sv_isobject(*handle)) {
            const char* package = HvNAME(SvSTASH(SvRV(*handle)));
            if (strEQ(package, "Net::SSH2::Channel")) {
                debug("- [%d] = channel\n", i);
                pollfd[i].type = LIBSSH2_POLLFD_CHANNEL;
                pollfd[i].fd.channel =
                 ((SSH2_CHANNEL*)SvIVX(GvSV((GV*)SvRV(*handle))))->channel;
            } else if(strEQ(package, "Net::SSH2::Listener")) {
                debug("- [%d] = listener\n", i);
                pollfd[i].type = LIBSSH2_POLLFD_LISTENER;
                pollfd[i].fd.listener =
                 ((SSH2_LISTENER*)SvIVX(SvRV(*handle)))->listener;
            } else {
                croak("%s::poll: invalid handle object in array (%d): %s",
                 class, i, package);
            }
        } else if(SvIOK(*handle)) {
            pollfd[i].type = LIBSSH2_POLLFD_SOCKET;
            pollfd[i].fd.socket = SvIV(*handle);
            debug("- [%d] = file(%d)\n", i, pollfd[i].fd.socket);
        } else {
            croak("%s::poll: invalid handle in array (%d): %s",
             class, i, SvPVbyte_nolen(*handle));
        }

        events = hv_fetch(hv, "events", 6, 0/*lval*/);
        if (!events || !*events || !SvIOK(*events)) {
            croak("%s::poll: bad or missing event mask in array (%d)",
             class, i);
        }
        pollfd[i].events = SvIV(*events);
        pollfd[i].revents = 0;
        debug("- [%d] events %d\n", i, pollfd[i].events);
    }
        
    changed = libssh2_poll(pollfd, count, timeout);
    debug("- libssh2_poll returned %d\n", changed);

    if (changed < 0)
        count = 0;
    for (i = 0; i < count; ++i) {
        HV* hv = (HV*)SvRV(*av_fetch(event, i, 0/*lval*/));
        hv_store(hv, "revents", 7, newSViv(pollfd[i].revents), 0/*hash*/);
        debug("- [%d] revents %d\n", i, pollfd[i].revents);
    }

    Safefree(pollfd);
    if (changed < 0)
        XSRETURN_EMPTY;
    XSRETURN_IV(changed);

SSH2_SFTP*
net_ss_sftp(SSH2* ss)
CODE:
    NEW_SFTP(libssh2_sftp_init(ss->session));
OUTPUT:
    RETVAL

SSH2_PUBLICKEY*
net_ss_public_key(SSH2* ss)
CODE:
    NEW_PUBLICKEY(libssh2_publickey_init(ss->session));
OUTPUT:
    RETVAL

#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::Channel    PREFIX = net_ch_
PROTOTYPES: DISABLE

#define class "Net::SSH2::Channel"

void
net_ch_DESTROY(SSH2_CHANNEL* ch)
CODE:
    debug("%s::DESTROY\n", class);
    libssh2_channel_free(ch->channel);
    SvREFCNT_dec(ch->sv_ss);
    Safefree(ch);

SV *
net_ch_session(SSH2_CHANNEL* ch)
CODE:
    RETVAL = newRV_inc(ch->sv_ss);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ch__setenv(SSH2_CHANNEL* ch, SV *key, SV *value)
PREINIT:
    int i, success = 0;
    const char* pv_key, * pv_value;
    STRLEN len_key, len_value;
CODE:
    pv_key = SvPVbyte(key, len_key);
    pv_value = SvPVbyte(value, len_value);
    RETVAL = libssh2_channel_setenv_ex(ch->channel,
                                       (char*)pv_key, len_key,
                                       (char*)pv_value, len_value);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x010208

void
net_ch__exit_signal(SSH2_CHANNEL* ch)
PREINIT:
    char *exitsignal;
    char *errmsg;
    char *langtag;
    size_t exitsignal_len;
    size_t errmsg_len;
    size_t langtag_len;
    int retcount = 1;
PPCODE:
    if (!libssh2_channel_get_exit_signal(ch->channel,
                                         &exitsignal, &exitsignal_len,
                                         &errmsg, &errmsg_len,
                                         &langtag, &langtag_len)) {
        LIBSSH2_SESSION *session = ch->ss->session;
        libssh2_session_set_last_error(session, 0, NULL);
        if (exitsignal) {
            XPUSHs(sv_2mortal(newSVpvn(exitsignal, exitsignal_len)));
            if (GIMME_V == G_ARRAY) {
                XPUSHs(errmsg ? sv_2mortal(newSVpvn(errmsg, errmsg_len)) : &PL_sv_undef);
                XPUSHs(langtag ? sv_2mortal(newSVpvn(langtag, langtag_len)) : &PL_sv_undef);
                retcount = 3;
            }
            libssh2_free(session, exitsignal);
            if (errmsg) libssh2_free(session, errmsg);
            if (langtag) libssh2_free(session, langtag);
        }
        else
            XPUSHs(&PL_sv_no);
        XSRETURN(retcount);
    }
    else
        XSRETURN(0);

#else

void
net_ch__exit_signal(SSH2_CHANNEL* ch)
CODE:
    croak("libssh2 version 1.2.8 or higher required for exit_signal support");

#endif

SSH2_BYTES
net_ch_eof(SSH2_CHANNEL* ch)
CODE:
    RETVAL = libssh2_channel_eof(ch->channel);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ch_send_eof(SSH2_CHANNEL* ch)
CODE:
    RETVAL = libssh2_channel_send_eof(ch->channel);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ch_close(SSH2_CHANNEL* ch)
CODE:
    RETVAL = libssh2_channel_close(ch->channel);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ch__wait_closed(SSH2_CHANNEL* ch)
CODE:
    RETVAL = libssh2_channel_wait_closed(ch->channel);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ch_wait_eof(SSH2_CHANNEL* ch)
CODE:
    RETVAL = libssh2_channel_wait_eof(ch->channel);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

int
net_ch__exit_status(SSH2_CHANNEL* ch)
CODE:
    RETVAL = libssh2_channel_get_exit_status(ch->channel);
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_MAJOR >= 1

SSH2_NERROR
net_ch__pty(SSH2_CHANNEL* ch, SV* terminal, SV* modes = NULL, \
            int width = 0, int height = 0)
PREINIT:
    const char* pv_terminal, * pv_modes = NULL;
    STRLEN len_terminal, len_modes = 0;
    int width_px = LIBSSH2_TERM_WIDTH_PX, height_px = LIBSSH2_TERM_HEIGHT_PX;
CODE:
    pv_terminal = SvPVbyte(terminal, len_terminal);
    if (modes && SvPOK(modes))
        pv_modes = SvPVbyte(modes, len_modes);
    if (!width)
        width = LIBSSH2_TERM_WIDTH;
    else if(width < 0) {
        width_px = -width;
        width = 0;
    }
    if (!height)
        height = LIBSSH2_TERM_HEIGHT;
    else if(height < 0) {
        height_px = -height;
        height = 0;
    }
    RETVAL = libssh2_channel_request_pty_ex(ch->channel,
                                            (char*)pv_terminal, len_terminal,
                                            (char*)pv_modes, len_modes,
                                            width, height, width_px, height_px);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_NERROR
net_ch_pty_size(SSH2_CHANNEL* ch, int width = 0, int height = 0)
PREINIT:
    int width_px = LIBSSH2_TERM_WIDTH_PX, height_px = LIBSSH2_TERM_HEIGHT_PX;
CODE:
    if (!width)
        croak("%s::pty_size: required parameter width missing", class);
    else if(width < 0) {
        width_px = -width;
        width = 0;
    }

    if (!height)
        croak("%s::pty_size: required parameter height missing", class);
    else if(height < 0) {
        height_px = -height;
        height = 0;
    }

    RETVAL = libssh2_channel_request_pty_size_ex(ch->channel,
                                                 width, height, width_px, height_px);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

#else

void
net_ch_pty(SSH2_CHANNEL* ch, SV* terminal, SV* modes = NULL, \
 int width = 0, int height = 0)
CODE:
    croak("libssh2 version 1.0 or higher required for PTY support");

void
net_ch_pty_size(SSH2_CHANNEL* ch, int width = 0, int height = 0)
CODE:
    croak("libssh2 version 1.0 or higher required for PTY support");

#endif

SSH2_NERROR
net_ch_process(SSH2_CHANNEL* ch, SV* request, SV* message = NULL)
PREINIT:
    const char* pv_request, * pv_message = NULL;
    STRLEN len_request, len_message = 0;
CODE:
    pv_request = SvPVbyte(request, len_request);
    if (message && SvPOK(message))
        pv_message = SvPVbyte(message, len_message);
    RETVAL = libssh2_channel_process_startup(ch->channel,
                                             pv_request, len_request,
                                             pv_message, len_message);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

int
net_ch_ext_data(SSH2_CHANNEL* ch, SSH2_CHANNEL_EXTENDED_DATA mode)
CODE:
    libssh2_channel_handle_extended_data(ch->channel, (int)mode);
    RETVAL = 1;
OUTPUT:
    RETVAL

SSH2_BYTES64
net_ch_read(SSH2_CHANNEL* ch, SV* buffer, size_t size = 32768, SSH2_STREAM_ID ext = 0)
PREINIT:
    char* pv_buffer;
    STRLEN len_buffer;
    int blocking, count = 0;
    size_t total = 0;
CODE:
    debug("%s::read(size = %d, ext = %d)\n", class, size, ext);
    sv_force_normal(buffer);
    sv_setpvn_mg(buffer, "", 0);
    SvPVbyte_force(buffer, len_buffer);
    pv_buffer = sv_grow(buffer, size + 1);
    blocking = libssh2_session_get_blocking(ch->ss->session);
    while (size) {
        count = libssh2_channel_read_ex(ch->channel, ext, pv_buffer, size);
        debug("- read %d bytes\n", count);
        if (count > 0) {
            total += count;
            pv_buffer += count;
            size -= count;
            if (blocking) break;
        }
        else {
            if ((count != LIBSSH2_ERROR_EAGAIN) || !blocking) break;
        }
    }
    debug("- read %d total\n", total);
    if (total || (count == 0)) {
        pv_buffer[0] = '\0';
        SvPOK_only(buffer);
        SvCUR_set(buffer, total);
        SvSETMAGIC(buffer);
        RETVAL = total;
    }
    else {
        SvOK_off(buffer);
        SvSETMAGIC(buffer);
        save_eagain(ch->ss->session, count);
        RETVAL = count;
    }
OUTPUT:
    RETVAL

SV *
net_ch_getc(SSH2_CHANNEL* ch, SSH2_STREAM_ID ext = 0)
PREINIT:
    char buffer[2];
    int count;
CODE:
    debug("%s::getc(ext = %d)\n", class, ext);
    count = libssh2_channel_read_ex(ch->channel, ext, buffer, 1);
    if (count >= 0) {
        buffer[count] = '\0';
        RETVAL = newSVpvn(buffer, count);
    }
    else {
        save_eagain(ch->ss->session, count);
        RETVAL = &PL_sv_undef;
    }
OUTPUT:
    RETVAL

SSH2_BYTES
net_ch_write(SSH2_CHANNEL* ch, SV* buffer, SSH2_STREAM_ID ext = 0)
PREINIT:
    const char* pv_buffer;
    STRLEN len_buffer, offset = 0;
    int count = 0;
CODE:
    /*
       1. in blocking mode, write all the data.
       2. in non-blocking mode, write as much data as possible without
          blocking.
       3. if some error happens...
          a. if some data was already written, discard the error and
             report the number of bytes written.
          b. if no data was written, report the error.
    */
    pv_buffer = SvPVbyte(buffer, len_buffer);
    while (offset < len_buffer) {
        count = libssh2_channel_write_ex(ch->channel, ext,
                                         pv_buffer + offset,
                                         len_buffer - offset);
        if (count >= 0)
            offset += count;
        else if ((count != LIBSSH2_ERROR_EAGAIN) ||
                 !libssh2_session_get_blocking(ch->ss->session))
            break;
    }
    if (offset || (count == 0)) /* yes, zero is a valid value */
        RETVAL = offset;
    else {
        save_eagain(ch->ss->session, count);
        RETVAL = -1;
    }
OUTPUT:
    RETVAL

#if LIBSSH2_VERSION_NUM >= 0x010100

SSH2_BYTES
net_ch_receive_window_adjust(SSH2_CHANNEL *ch, unsigned long adjustment, SV *force = &PL_sv_undef)
PREINIT:
    unsigned int bytes;
CODE:
    RETVAL = libssh2_channel_receive_window_adjust2(ch->channel, adjustment,
                                                    SvTRUE(force), &bytes);
    if (RETVAL)
        save_eagain(ch->ss->session, RETVAL);
    else
        RETVAL = bytes;
OUTPUT:
    RETVAL

#else

void
net_ch_receive_window_adjust(SSH2_CHANNEL* ch, ...)
CODE:
    croak("libssh2 version 1.1 or higher required for receive_window_adjust support");

#endif

#if LIBSSH2_VERSION_NUM >= 0x010200

void
net_ch_window_write(SSH2_CHANNEL* ch)
PREINIT:
    unsigned long window_size_initial = 0;
PPCODE:
    XPUSHs(sv_2mortal(newSVuv(libssh2_channel_window_write_ex(ch->channel,
                                                              &window_size_initial))));
    if (GIMME_V == G_ARRAY) {
        XPUSHs(sv_2mortal(newSVuv(window_size_initial)));
        XSRETURN(2);
    }
    else
        XSRETURN(1);

void
net_ch_window_read(SSH2_CHANNEL *ch)
PREINIT:
    unsigned long read_avail = 0;
    unsigned long window_size_initial = 0;
PPCODE:
    XPUSHs(sv_2mortal(newSVuv(libssh2_channel_window_read_ex(ch->channel,
                                                             &read_avail,
                                                             &window_size_initial))));
    if (GIMME_V == G_ARRAY) {
        XPUSHs(sv_2mortal(newSVuv(read_avail)));
        XPUSHs(sv_2mortal(newSVuv(window_size_initial)));
        XSRETURN(3);
    }
    else
        XSRETURN(1);

#else

void
net_ch_window_write(SSH2_CHANNEL* ch)
CODE:
    croak("libssh2 version 1.2 or higher required for window_write support");

void
net_ch_window_read(SSH2_CHANNEL* ch)
CODE:
    croak("libssh2 version 1.2 or higher required for window_read support");

#endif

SSH2_BYTES
net_ch_flush(SSH2_CHANNEL* ch, SSH2_STREAM_ID ext = 0)
CODE:
    RETVAL = libssh2_channel_flush_ex(ch->channel, ext);
    save_eagain(ch->ss->session, RETVAL);
OUTPUT:
    RETVAL

#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::Listener    PREFIX = net_ls_
PROTOTYPES: DISABLE

#define class "Net::SSH2::Listener"

void
net_ls_DESTROY(SSH2_LISTENER* ls)
CODE:
    debug("%s::DESTROY\n", class);
    libssh2_channel_forward_cancel(ls->listener);
    SvREFCNT_dec(ls->sv_ss);
    Safefree(ls);

SSH2_CHANNEL*
net_ls_accept(SSH2_LISTENER* ls)
PREINIT:
    SSH2* ss;
CODE:
    ss = ls->ss;
    NEW_CHANNEL(libssh2_channel_forward_accept(ls->listener));
OUTPUT:
    RETVAL

#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::SFTP   PREFIX = net_sf_
PROTOTYPES: DISABLE

#define class "Net::SSH2::SFTP"

void
net_sf_DESTROY(SSH2_SFTP* sf)
CODE:
    debug("%s::DESTROY\n", class);
    libssh2_sftp_shutdown(sf->sftp);
    debug("%s::DESTROY freeing session\n", class);
    SvREFCNT_dec(sf->sv_ss);
    Safefree(sf);

SV *
net_sf_session(SSH2_SFTP* sf)
CODE:
    RETVAL = newRV_inc(sf->sv_ss);
OUTPUT:
    RETVAL

void
net_sf_error(SSH2_SFTP* sf)
PREINIT:
    unsigned long error;
    SV *errstr;
PPCODE:
    error = libssh2_sftp_last_error(sf->sftp);
    ST(0) = sv_2mortal(newSVuv(error));
    if (GIMME_V == G_ARRAY) {
        EXTEND(SP, 2);
        if ((error >= 0) && (error < countof(sftp_error)))
            errstr = newSVpvf("SSH_FX_%s", sftp_error[error]);
        else
            errstr = newSVpvf("SSH_FX_UNKNOWN(%lu)", error);
        ST(1) = sv_2mortal(errstr);
        XSRETURN(2);
    }
    else
        XSRETURN(1);

#define XLATFLAG(posix, fxf) do { \
    if (flags & posix || \
     l_flags == 0 && posix == 0 && flags == posix /* 0-valued flag */) { \
        l_flags |= fxf; \
        flags &= ~posix; \
    } \
} while(0)
    
SSH2_FILE*
net_sf_open(SSH2_SFTP* sf, SV* file, int flags = O_RDONLY, int mode = 0666)
PREINIT:
    long l_flags = 0;
    const char* pv_file;
    STRLEN len_file;
CODE:
    pv_file = SvPVbyte(file, len_file);
    
    /* map POSIX O_* to LIBSSH2_FXF_* (can't assume they're the same) */
    XLATFLAG(O_RDWR,   LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE);
    XLATFLAG(O_RDONLY, LIBSSH2_FXF_READ);
    XLATFLAG(O_WRONLY, LIBSSH2_FXF_WRITE);
    XLATFLAG(O_APPEND, LIBSSH2_FXF_APPEND);
    XLATFLAG(O_CREAT,  LIBSSH2_FXF_CREAT);
    XLATFLAG(O_TRUNC,  LIBSSH2_FXF_TRUNC);
    XLATFLAG(O_EXCL,   LIBSSH2_FXF_EXCL);
    if (flags)
        croak("%s::open: unknown flag value: %d", class, flags);

    NEW_FILE(libssh2_sftp_open_ex(sf->sftp, (char*)pv_file, len_file,
     l_flags, mode, LIBSSH2_SFTP_OPENFILE));
OUTPUT:
    RETVAL

#undef XLATFLAG

SSH2_DIR*
net_sf_opendir(SSH2_SFTP* sf, SV* dir)
PREINIT:
    const char* pv_dir;
    STRLEN len_dir;
CODE:
    pv_dir = SvPVbyte(dir, len_dir);
    NEW_DIR(libssh2_sftp_open_ex(sf->sftp, (char*)pv_dir, len_dir,
     0/*flags*/, 0/*mode*/, LIBSSH2_SFTP_OPENDIR));
OUTPUT:
    RETVAL

SSH2_NERROR
net_sf_unlink(SSH2_SFTP* sf, SV* file)
PREINIT:
    char* pv_file;
    STRLEN len_file;
CODE:
    pv_file = SvPVbyte(file, len_file);
    RETVAL = libssh2_sftp_unlink_ex(sf->sftp, (char*)pv_file, len_file);
OUTPUT:
    RETVAL

SSH2_NERROR
net_sf_rename(SSH2_SFTP* sf, SV* old, SV* new,                  \
              long flags = ( LIBSSH2_SFTP_RENAME_OVERWRITE |    \
                             LIBSSH2_SFTP_RENAME_ATOMIC    |    \
                             LIBSSH2_SFTP_RENAME_NATIVE ) )
PREINIT:
    const char* pv_old, * pv_new;
    STRLEN len_old, len_new;
CODE:
    pv_old = SvPVbyte(old, len_old);
    pv_new = SvPVbyte(new, len_new);
    RETVAL = libssh2_sftp_rename_ex(sf->sftp,
                                    (char*)pv_old, len_old, (char*)pv_new, len_new, flags);
OUTPUT:
    RETVAL

SSH2_NERROR
net_sf_mkdir(SSH2_SFTP* sf, SV* dir, int mode = 0777)
PREINIT:
    const char* pv_dir;
    STRLEN len_dir;
CODE:
    pv_dir = SvPVbyte(dir, len_dir);
    RETVAL = libssh2_sftp_mkdir_ex(sf->sftp, (char*)pv_dir, len_dir, mode);
OUTPUT:
    RETVAL

SSH2_NERROR
net_sf_rmdir(SSH2_SFTP* sf, SV* dir)
PREINIT:
    const char* pv_dir;
    STRLEN len_dir;
CODE:
    pv_dir = SvPVbyte(dir, len_dir);
    RETVAL = libssh2_sftp_rmdir_ex(sf->sftp, (char*)pv_dir, len_dir);
OUTPUT:
    RETVAL

void
net_sf_stat(SSH2_SFTP* sf, SV* path, int follow = 1)
PREINIT:
    const char* pv_path;
    STRLEN len_path;
    int error;
    LIBSSH2_SFTP_ATTRIBUTES attrs;
PPCODE:
    pv_path = SvPVbyte(path, len_path);
    error = libssh2_sftp_stat_ex(sf->sftp, (char*)pv_path, len_path,
                                  (follow ? LIBSSH2_SFTP_STAT : LIBSSH2_SFTP_LSTAT),
                                  &attrs);
    if (error < 0)
        XSRETURN_EMPTY;
    XSRETURN_STAT_ATTRS(SvREFCNT_inc(path));

SSH2_NERROR
net_sf_setstat(SSH2_SFTP* sf, SV* path, ...)
PREINIT:
    const char* pv_path;
    STRLEN len_path;
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int i;
CODE:
    pv_path = SvPVbyte(path, len_path);
    Zero(&attrs, 1, LIBSSH2_SFTP_ATTRIBUTES);

    /* read key/value pairs; cf. hv_from_attrs */
    for (i = 2; i < items; i += 2) {
        const char* key = SvPVbyte_nolen(ST(i));
        if (i + 1 == items)
            croak("%s::setstat: key without value", class);
        if (0);  /* prime the chain */
        XLATATTR("size",  filesize,    SIZE)
        XLATATTR("uid",   uid,         UIDGID)
        XLATATTR("gid",   gid,         UIDGID)
        XLATATTR("mode",  permissions, PERMISSIONS)
        XLATATTR("atime", atime,       ACMODTIME)
        XLATATTR("mtime", mtime,       ACMODTIME)
        else
            croak("%s::setstat: unknown attribute: %s", class, key);
    }
    RETVAL = libssh2_sftp_stat_ex(sf->sftp, (char*)pv_path, len_path,
                                  LIBSSH2_SFTP_SETSTAT, &attrs);
OUTPUT:
    RETVAL

SSH2_NERROR
net_sf_symlink(SSH2_SFTP* sf, SV* path, SV* target)
PREINIT:
    char *pv_path, *pv_target;
    STRLEN len_path, len_target;
CODE:
    pv_path = SvPVbyte(path, len_path);
    pv_target = SvPVbyte(target, len_target);
    RETVAL = libssh2_sftp_symlink_ex(sf->sftp,
                                     pv_path, len_path,
                                     pv_target, len_target,
                                     LIBSSH2_SFTP_SYMLINK);
OUTPUT:
    RETVAL

SV *
net_sf_readlink(SSH2_SFTP* sf, SV* path)
PREINIT:
    const char* pv_path;
    char* pv_link;
    STRLEN len_path;
    int count;
CODE:
    pv_path = SvPVbyte(path, len_path);
    RETVAL = newSV(MAXPATHLEN + 1);
    pv_link = SvPVX(RETVAL);
    count = libssh2_sftp_symlink_ex(sf->sftp,
                                    pv_path, len_path,
                                    pv_link, MAXPATHLEN,
                                    LIBSSH2_SFTP_READLINK);
    if (count >= 0) {
        SvPOK_on(RETVAL);
        pv_link[count] = '\0';
        SvCUR_set(RETVAL, count);
    }
OUTPUT:
    RETVAL

SV *
net_sf_realpath(SSH2_SFTP* sf, SV* path)
PREINIT:
    const char* pv_path;
    char* pv_real;
    STRLEN len_path;
    int count;
CODE:
    pv_path = SvPVbyte(path, len_path);
    RETVAL = newSV(MAXPATHLEN + 1);
    pv_real = SvPVX(RETVAL);
    count = libssh2_sftp_symlink_ex(sf->sftp,
                                    pv_path, len_path,
                                    pv_real, MAXPATHLEN,
                                    LIBSSH2_SFTP_REALPATH);
    if (count >= 0) {
        SvPOK_on(RETVAL);
        pv_real[count] = '\0';
        SvCUR_set(RETVAL, count);
    }
OUTPUT:
    RETVAL

#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::File   PREFIX = net_fi_
PROTOTYPES: DISABLE

#define class "Net::SSH2::File"

void
net_fi_DESTROY(SSH2_FILE* fi)
CODE:
    debug("%s::DESTROY\n", class);
    libssh2_sftp_close_handle(fi->handle);
    SvREFCNT_dec(fi->sv_sf);
    Safefree(fi);

SSH2_BYTES
net_fi_read(SSH2_FILE* fi, SV* buffer, size_t size)
PREINIT:
    char* pv_buffer;
    STRLEN len_buffer;
CODE:
    sv_force_normal(buffer);
    sv_setpvn_mg(buffer, "", 0);
    SvPVbyte_force(buffer, len_buffer);
    pv_buffer = sv_grow(buffer, size + 1);
    RETVAL = libssh2_sftp_read(fi->handle, pv_buffer, size);
    if (RETVAL < 0)
        SvOK_off(buffer);
    else {
        SvPOK_only(buffer);
        pv_buffer[RETVAL] = '\0';
        SvCUR_set(buffer, RETVAL);
    }
    SvSETMAGIC(buffer);
OUTPUT:
    RETVAL

SV *
net_fi_getc(SSH2_FILE* fi)
PREINIT:
    char buffer[2];
    int count;
CODE:
    count = libssh2_sftp_read(fi->handle, buffer, 1);
    if (count == 1) {
        buffer[count] = '\0';
        RETVAL = newSVpvn(buffer, count);
    }
    else
        RETVAL = &PL_sv_undef;
OUTPUT:
    RETVAL

SSH2_BYTES
net_fi_write(SSH2_FILE* fi, SV* buffer)
PREINIT:
    const char* pv_buffer;
    STRLEN len_buffer;
CODE:
    sv_utf8_downgrade(buffer, 0);
    pv_buffer = SvPVbyte(buffer, len_buffer);
    RETVAL = libssh2_sftp_write(fi->handle, pv_buffer, len_buffer);
OUTPUT:
    RETVAL

void
net_fi_stat(SSH2_FILE* fi)
PREINIT:
    LIBSSH2_SFTP_ATTRIBUTES attrs;
PPCODE:
    if (libssh2_sftp_fstat(fi->handle, &attrs))
        XSRETURN_EMPTY;
    XSRETURN_STAT_ATTRS(NULL/*name*/);

SSH2_NERROR
net_fi_setstat(SSH2_FILE* fi, ...)
PREINIT:
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int i;
CODE:
    Zero(&attrs, 1, LIBSSH2_SFTP_ATTRIBUTES);

    /* read key/value pairs; cf. hv_from_attrs */
    for (i = 1; i < items; i += 2) {
        const char* key = SvPVbyte_nolen(ST(i));
        if (i + 1 == items)
            croak("%s::setstat: key without value", class);
        if (0);  /* prime the chain */
        XLATATTR("size",  filesize,    SIZE)
        XLATATTR("uid",   uid,         UIDGID)
        XLATATTR("gid",   gid,         UIDGID)
        XLATATTR("mode",  permissions, PERMISSIONS)
        XLATATTR("atime", atime,       ACMODTIME)
        XLATATTR("mtime", mtime,       ACMODTIME)
        else
            croak("%s::setstat: unknown attribute: %s", class, key);
    }
    RETVAL = libssh2_sftp_fsetstat(fi->handle, &attrs);
OUTPUT:
    RETVAL

int
net_fi_seek(SSH2_FILE* fi, size_t offset)
CODE:
    libssh2_sftp_seek64(fi->handle, offset);
    RETVAL = 1;
OUTPUT:
    RETVAL

SSH2_BYTES64
net_fi_tell(SSH2_FILE* fi)
CODE:
    RETVAL = libssh2_sftp_tell64(fi->handle);
OUTPUT:
    RETVAL
        
#undef class

MODULE = Net::SSH2		PACKAGE = Net::SSH2::Dir   PREFIX = net_di_
PROTOTYPES: DISABLE

#define class "Net::SSH2::Dir"

void
net_di_DESTROY(SSH2_DIR* di)
CODE:
    debug("%s::DESTROY\n", class);
    libssh2_sftp_close_handle(di->handle);
    SvREFCNT_dec(di->sv_sf);
    Safefree(di);

void
net_di_read(SSH2_DIR* di)
PREINIT:
    SV* buffer;
    char* pv_buffer;
    int count;
    LIBSSH2_SFTP_ATTRIBUTES attrs;
PPCODE:
    buffer = newSV(MAXPATHLEN + 1);
    SvPOK_on(buffer);
    pv_buffer = SvPVX(buffer);

    count = libssh2_sftp_readdir(di->handle, pv_buffer, MAXPATHLEN, &attrs);

    if (count <= 0) {
        SvREFCNT_dec(buffer);
        XSRETURN_EMPTY;
    }
    pv_buffer[count] = '\0';
    SvCUR_set(buffer, count);
    XSRETURN_STAT_ATTRS(buffer);

#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::PublicKey   PREFIX = net_pk_
PROTOTYPES: DISABLE

#define class "Net::SSH2::PublicKey"

void
net_pk_DESTROY(SSH2_PUBLICKEY* pk)
CODE:
    debug("%s::DESTROY\n", class);
    libssh2_publickey_shutdown(pk->pkey);
    SvREFCNT_dec(pk->sv_ss);
    Safefree(pk);

SSH2_NERROR
net_pk_add(SSH2_PUBLICKEY* pk, SV* name, SV* blob, int overwrite, ...)
PREINIT:
    const char* pv_name, * pv_blob;
    STRLEN len_name, len_blob;
    unsigned long num_attrs, i;
    libssh2_publickey_attribute *attrs;
CODE:
    pv_name = SvPVbyte(name, len_name);
    pv_blob = SvPVbyte(blob, len_blob);

    num_attrs = items - 4;
    New(0, attrs, num_attrs, libssh2_publickey_attribute);
    if (!attrs)
        Perl_croak(aTHX_ "Out of memory!");

    for (i = 0; i < num_attrs; ++i) {
        HV* hv;
        SV** tmp;
        STRLEN len_tmp;

        if (!SvROK(ST(i + 4)) || SvTYPE(SvRV(ST(i + 4))) != SVt_PVHV)
            croak("%s::add: attribute %lu is not hash", class, i);
        hv = (HV*)SvRV(ST(i + 4));

        if (!(tmp = hv_fetch(hv, "name", 4, 0/*lval*/)) || !*tmp)
            croak("%s::add: attribute %lu missing name", class, i);
        attrs[i].name = SvPVbyte(*tmp, len_tmp);
        attrs[i].name_len = len_tmp;

        if ((tmp = hv_fetch(hv, "value", 5, 0/*lval*/)) && *tmp) {
            attrs[i].value = SvPVbyte(*tmp, len_tmp);
            attrs[i].value_len = len_tmp;
        } else
            attrs[i].value_len = 0;

        if ((tmp = hv_fetch(hv, "mandatory", 9, 0/*lval*/)) && *tmp)
            attrs[i].mandatory = (char)SvIV(*tmp);
        else
            attrs[i].mandatory = 0;
    }

    RETVAL = libssh2_publickey_add_ex(pk->pkey,
                                      (const unsigned char *)pv_name, len_name,
                                      (const unsigned char *)pv_blob, len_blob, overwrite, num_attrs, attrs);
    Safefree(attrs);
OUTPUT:
    RETVAL
    
SSH2_NERROR
net_pk_remove(SSH2_PUBLICKEY* pk, SV* name, SV* blob)
PREINIT:
    const char* pv_name, * pv_blob;
    STRLEN len_name, len_blob;
CODE:
    pv_name = SvPVbyte(name, len_name);
    pv_blob = SvPVbyte(blob, len_blob);
    RETVAL = libssh2_publickey_remove_ex(pk->pkey,
                                         (const unsigned char *)pv_name, len_name,
                                         (const unsigned char *)pv_blob, len_blob);
OUTPUT:
    RETVAL

void
net_pk_fetch(SSH2_PUBLICKEY* pk)
PREINIT:
    unsigned long keys, i, j;
    libssh2_publickey_list* list = NULL;
PPCODE:
    if (!libssh2_publickey_list_fetch(pk->pkey, &keys, &list) || !list)
        XSRETURN_EMPTY;

    if (GIMME_V == G_ARRAY) {
        EXTEND(SP, keys);

        for (i = 0; i < keys; ++i) {
            HV* hv = newHV();
            AV* av = newAV();

            hv_store(hv, "name", 4,
             newSVpvn((char*)list[i].name, list[i].name_len), 0/*hash*/);
            hv_store(hv, "blob", 4,
             newSVpvn((char*)list[i].blob, list[i].blob_len), 0/*hash*/);

            hv_store(hv, "attr", 4, newRV_noinc((SV*)av), 0/*hash*/);
            av_extend(av, list[i].num_attrs - 1);
            for (j = 0; j < list[i].num_attrs; ++j) {
                HV* attr = newHV();
                hv_store(attr, "name", 4, newSVpvn(list[i].attrs[j].name,
                 list[i].attrs[j].name_len), 0/*hash*/);
                hv_store(attr, "value", 5, newSVpvn(list[i].attrs[j].value,
                 list[i].attrs[j].value_len), 0/*hash*/);
                hv_store(attr, "mandatory", 9,
                 newSViv(list[i].attrs[j].mandatory), 0/*hash*/);
                av_store(av, j, newRV_noinc((SV*)attr));
            }
            
            ST(i) = sv_2mortal(newRV_noinc((SV*)hv));
        }
    }

    libssh2_publickey_list_free(pk->pkey, list);

    if (GIMME_V == G_ARRAY)
        XSRETURN(keys);
    XSRETURN_UV(keys);

#undef class

MODULE = Net::SSH2		PACKAGE = Net::SSH2::KnownHosts   PREFIX = net_kh_
PROTOTYPES: DISABLE

#define class "Net::SSH2::KnownHosts"

#if LIBSSH2_VERSION_NUM >= 0x010200

void
net_kh_DESTROY(SSH2_KNOWNHOSTS *kh)
CODE:
    debug("%s::DESTROY\n", class);
    libssh2_knownhost_free(kh->knownhosts);
    SvREFCNT_dec(kh->sv_ss);
    Safefree(kh);

SSH2_BYTES
net_kh_readfile(SSH2_KNOWNHOSTS *kh, SSH2_CHARP filename)
CODE:
    RETVAL = libssh2_knownhost_readfile(kh->knownhosts, filename, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
OUTPUT:
    RETVAL

SSH2_NERROR
net_kh_writefile(SSH2_KNOWNHOSTS *kh, SSH2_CHARP filename)
CODE:
    RETVAL = libssh2_knownhost_writefile(kh->knownhosts, filename, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    save_eagain(kh->ss->session, RETVAL);
OUTPUT:
    RETVAL

SSH2_NERROR
net_kh_add(SSH2_KNOWNHOSTS *kh, SSH2_CHARP host, SSH2_CHARP salt, SV *key, SV *comment, int typemask)
PREINIT:
    STRLEN key_len, comment_len;
    const char *key_pv, *comment_pv;
CODE:
    key_pv = SvPVbyte(key, key_len);
    if (SvOK(comment))
        comment_pv = SvPVbyte(comment, comment_len);
    else {
        comment_pv = NULL;
        comment_len = 0;
    }
#if LIBSSH2_VERSION_NUM >= 0x010205
    RETVAL = libssh2_knownhost_addc(kh->knownhosts, host, salt, key_pv, key_len,
                                    comment_pv, comment_len, typemask, NULL);
#else
    RETVAL = libssh2_knownhost_add(kh->knownhosts, host, salt, key_pv, key_len,
                                   typemask, NULL);
#endif
    save_eagain(kh->ss->session, RETVAL);
OUTPUT:
    RETVAL

int
net_kh_check(SSH2_KNOWNHOSTS *kh, SSH2_CHARP host, SV *port, SV *key, int typemask)
PREINIT:
    STRLEN key_len;
    const char *key_pv;
    UV port_uv;
CODE:
    key_pv = SvPVbyte(key, key_len);
    port_uv = (SvOK(port) ? SvUV(port) : 0);
#if LIBSSH2_VERSION_NUM >= 0x010206
    RETVAL = libssh2_knownhost_checkp(kh->knownhosts, host, port_uv,
                                      key_pv, key_len, typemask, NULL);
#else
    if ((port_uv != 0) && (port_uv != 22))
        croak("libssh2 version 1.2.6 is required when using a custom TCP port");
    RETVAL = libssh2_knownhost_check(kh->knownhosts, host,
                                     key_pv, key_len, typemask, NULL);
#endif
OUTPUT:
    RETVAL

SSH2_NERROR
net_kh_readline(SSH2_KNOWNHOSTS *kh, SV *line)
PREINIT:
    STRLEN line_len;
    const char *line_pv;
CODE:
    line_pv = SvPVbyte(line, line_len);
    RETVAL = libssh2_knownhost_readline(kh->knownhosts, line_pv, line_len, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    save_eagain(kh->ss->session, RETVAL);
OUTPUT:
    RETVAL

SV *
net_kh_writeline(SSH2_KNOWNHOSTS *kh, SSH2_CHARP host, SV *port, SV *key, int typemask)
PREINIT:
    int rc;
    STRLEN key_len;
    const char *key_pv;
    UV port_uv;
    size_t line_len;
    STRLEN buffer_len;
    SV *buffer;
    struct libssh2_knownhost *entry = NULL;
CODE:
    RETVAL = &PL_sv_undef;
    key_pv = SvPVbyte(key, key_len);
    port_uv = (SvOK(port) ? SvUV(port) : 0);
#if LIBSSH2_VERSION_NUM >= 0x010206
    rc = libssh2_knownhost_checkp(kh->knownhosts, host, port_uv,
                                  key_pv, key_len, typemask, &entry);
#else
    if ((port_uv != 0) && (port_uv != 22))
        croak("libssh2 version 1.2.6 is required when using a custom TCP port");
    rc = libssh2_knownhost_check(kh->knownhosts, host,
                                 key_pv, key_len, typemask, &entry);
#endif
    if ((rc != LIBSSH2_KNOWNHOST_CHECK_MATCH) || !entry) {
#if LIBSSH2_VERSION_NUM >= 0x010601
        libssh2_session_set_last_error(kh->ss->session, LIBSSH2_ERROR_KNOWN_HOSTS, "matching host key not found");
#endif
    }
    else {
        buffer = sv_2mortal(newSV(512));
        SvPOK_on(buffer);
        while (1) {
            rc = libssh2_knownhost_writeline(kh->knownhosts, entry,
                                             SvPVX(buffer), SvLEN(buffer),
                                             &line_len, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
            if (rc == LIBSSH2_ERROR_NONE) {
                SvPVX(buffer)[line_len] = '\0';
                SvCUR_set(buffer, line_len);
                RETVAL = SvREFCNT_inc(buffer);
                break;
            }

            if ((rc != LIBSSH2_ERROR_BUFFER_TOO_SMALL) ||
                (SvLEN(buffer) > 256 * 1024)) break;

            SvGROW(buffer, SvLEN(buffer) * 2);
        }
    }
OUTPUT:
    RETVAL

# /* TODO */
# libssh2_knownhost_del()
# libssh2_knownhost_get()
# libssh2_knownhost_writeline()

#endif

#undef class

# vim: set et ts=4:
