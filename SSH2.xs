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

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <libssh2_publickey.h>


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
    "EAGAIN"
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

#define XLATEXT (SvTRUE(ext) ? SSH_EXTENDED_DATA_STDERR : 0)

#define XLATATTR(name, field, flag) \
    else if (strEQ(key, name)) { \
        attrs.field = SvUV(ST(i + 1)); \
        attrs.flags |= LIBSSH2_SFTP_ATTR_##flag; \
    }

/* Net::SSH2 object */
typedef struct SSH2 {
    LIBSSH2_SESSION* session;
    SV* sv_ss;  /* NB: not set until callback() called */
    SV* socket;
    SV* sv_tmp;
    int errcode;
    SV* errmsg;
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
static unsigned long net_ch_gensym = 0;
static unsigned long net_fi_gensym = 0;

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

/* set Net:SSH2-specific error message */
static void set_error(SSH2* ss, int errcode, const char* errmsg) {
    ss->errcode = errcode;
    if (ss->errmsg)
        SvREFCNT_dec(ss->errmsg);
    ss->errmsg = errmsg ? newSVpv(errmsg, 0) : NULL;
}    

/* clear our local error flag */
static void clear_error(SSH2* ss) {
    set_error(ss, LIBSSH2_ERROR_NONE, NULL/*errmsg*/);
}

/* split a string at commas and push each substring onto the perl stack */
static int split_comma(SV** sp, const char* str) {
    int i;
    const char* p;

    if (!str || !*str)
        return 0;

    i = 1;
    while ((p = strchr(str, ','))) {
        mXPUSHp(str, p - str);
        str = p + 1;
        ++i;
    }
    mXPUSHp(str, strlen(str));
    return i;
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

/* return NULL if undef or NULL, else return string */
static const char* default_string(SV* sv) {
    return (sv && SvPOK(sv)) ? SvPV_nolen(sv) : NULL;
}

/* return an integer constant from an SV name or value */
static int iv_constant_sv(const char *prefix, SV* c_sv, IV* piv) {
    int ret = 1;

    /* accept type as constant, constant without prefix, or numeric value */
    if (SvIOK(c_sv)) {
        *piv = SvIV(c_sv);
    } else {
        SV *sv = newSVsv(c_sv);
        char* str = SvPV_nolen(sv), * p;
        const char* pv;
        STRLEN len = strlen(prefix);

        for (p = str; *p; ++p)
            *p = toUPPER(*p);
        if (strncmp(str, prefix, len))
            sv_insert(sv, 0/*offset*/, 0/*replace*/, (char*)prefix, len);
        pv = SvPV(sv, len);
	    if (constant(aTHX_ pv, len, piv) != PERL_constant_ISIV)
            ret = 0;
        SvREFCNT_dec(sv);
    }
    return ret;
}

/* create a hash from an SFTP attributes structure */
static HV* hv_from_attrs(LIBSSH2_SFTP_ATTRIBUTES* attrs) {
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

/* callback for returning a password via "keyboard-interactive" auth */
static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(cb_kbdint_response_password) {
    SSH2* ss = (SSH2*)*abstract;
    const char* pv_password;
    STRLEN len_password;

    if (num_prompts != 1 || prompts[0].echo) {
        int i;
        for (i = 0; i < num_prompts; ++i)
            responses[i].length = 0;
        return;
     }

    /* single prompt, no echo: assume it's a password request */
    pv_password = SvPV(ss->sv_tmp, len_password);
    New(0, responses[0].text, len_password, char);
    Copy(pv_password, responses[0].text, len_password, char);
    responses[0].length = len_password;
}

/* thunk to call perl input-reading function for "keyboard-interactive" auth */
static LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(cb_kbdint_response_callback) {
    SSH2* ss = (SSH2*)*abstract;
    int i;

    dSP; I32 ax; int count;
    ENTER; SAVETMPS; PUSHMARK(SP);
    EXTEND(SP, 4 + num_prompts);
    PUSHs(*av_fetch((AV*)ss->sv_tmp, 1, 0/*lval*/));
    PUSHs(*av_fetch((AV*)ss->sv_tmp, 2, 0/*lval*/));
    PUSHs(sv_2mortal(newSVpvn(name, name_len)));
    PUSHs(sv_2mortal(newSVpvn(instruction, instruction_len)));
    for (i = 0; i < num_prompts; ++i) {
        HV* hv = newHV();
        responses[i].length = 0;
        hv_store(hv, "text", 4, newSVpvn(prompts[i].text, prompts[i].length),
         0/*hash*/);
        hv_store(hv, "echo", 4, newSViv(prompts[i].echo), 0/*hash*/);
        PUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
    }
    PUTBACK;

    count = call_sv(*av_fetch((AV*)ss->sv_tmp, 0, 0/*lval*/), G_ARRAY);
    SPAGAIN; SP -= count; ax = (SP - PL_stack_base) + 1;

    /* translate the returned responses */
    for (i = 0; i < count; ++i) {
        STRLEN len_response;
        const char* pv_response = SvPV(ST(i), len_response);
        New(0, responses[i].text, len_response, char);
        Copy(pv_response, responses[i].text, len_response, char);
        responses[i].length = len_response;
    }

    PUTBACK; FREETMPS; LEAVE;
}

/* thunk to call perl password change function for "password" auth */
static LIBSSH2_PASSWD_CHANGEREQ_FUNC(cb_password_change_callback) {
    SSH2* ss = (SSH2*)*abstract;

    dSP; I32 ax; int count;
    ENTER; SAVETMPS; PUSHMARK(SP);
    XPUSHs(*av_fetch((AV*)ss->sv_tmp, 1, 0/*lval*/));
    XPUSHs(*av_fetch((AV*)ss->sv_tmp, 2, 0/*lval*/));
    PUTBACK;

    *newpw = NULL;
    *newpw_len = 0;
    count = call_sv(*av_fetch((AV*)ss->sv_tmp, 0, 0/*lval*/), G_SCALAR);
    SPAGAIN; SP -= count; ax = (SP - PL_stack_base) + 1;

    if (count > 0) {
        STRLEN len_password;
        const char* pv_password = SvPV(ST(0), len_password);
        New(0, *newpw, len_password, char);
        Copy(pv_password, *newpw, len_password, char);
        *newpw_len = len_password;
    }

    PUTBACK; FREETMPS; LEAVE;
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
croak_last_error(SSH2 *ss, const char *klass, const char *method) {
    char *errmsg;
    if ((ss->errcode != LIBSSH2_ERROR_NONE) && (ss->errmsg != NULL))
        errmsg = SvPV_nolen(ss->errmsg);
    else {
        if (libssh2_session_last_error(ss->session, &errmsg, NULL, 0) == LIBSSH2_ERROR_NONE)
            croak("Internal error: croak_last_error called but there was no error!");
    }
    croak("%s::%s: %s", klass, method, errmsg);
}

#define CROAK_LAST_ERROR(session, method) (croak_last_error((session), class, (method)))

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
    clear_error(RETVAL);

    debug("Net::SSH2: created new object 0x%x\n", RETVAL);
OUTPUT:
    RETVAL

void
net_ss_trace(SSH2* ss, SV* bitmask)
CODE:
    libssh2_trace(ss->session, SvIV(bitmask));

#if LIBSSH2_VERSION_MAJOR >= 1

SV*
net_ss_block_directions(SSH2* ss)
CODE:
    RETVAL = newSViv((IV)libssh2_session_block_directions(ss->session));
OUTPUT:
    RETVAL

#else

void
net_ss_block_directions(SSH2* ss)
CODE:
    croak("libssh2 version 1.0 or higher required for block_directions support");

#endif

#if LIBSSH2_VERSION_NUM >= 0x010209

void
net_ss_timeout(SSH2* ss, long timeout)
CODE:
    libssh2_session_set_timeout(ss->session, timeout);

#else

void
net_ss_timeout(SSH2* ss, long timeout)
CODE:
    croak("libssh2 version 1.2.9 or higher required for set_timeout support");

#endif

void
net_ss_blocking(SSH2* ss, SV* blocking)
CODE:
    clear_error(ss);
    libssh2_session_set_blocking(ss->session, SvTRUE(blocking));
    XSRETURN_IV(1);

void
net_ss_DESTROY(SSH2* ss)
CODE:
    debug("%s::DESTROY object 0x%x\n", class, ss);
    clear_error(ss);
    libssh2_session_free(ss->session);
    SvREFCNT_dec(ss->socket);
    Safefree(ss);

void
net_ss_debug(SV*, SV* debug)
CODE:
    net_ss_debug_out = SvIV(debug) & 1;  /* allow for future flags */

void
net_ss_version(SV* name = NULL)
CODE:
    switch (GIMME_V) {
    case G_SCALAR:
        XSRETURN_PV(LIBSSH2_VERSION);
    case G_ARRAY:
        EXTEND(SP, 3);
        ST(0) = sv_2mortal(newSVpv(LIBSSH2_VERSION, 0));
#ifdef LIBSSH2_VERSION_NUM
        ST(1) = sv_2mortal(newSVuv(LIBSSH2_VERSION_NUM));
#else
        ST(1) = &PL_sv_undef;
#endif
        ST(2) = sv_2mortal(newSVpv(LIBSSH2_SSH_DEFAULT_BANNER, 0));
        XSRETURN(3);
    }

void
net_ss_banner(SSH2* ss, SV* banner)
PREINIT:
    int success;
    SV* sv_banner;
CODE:
    clear_error(ss);
    sv_banner = newSVsv(banner);
    sv_insert(sv_banner, 0/*offset*/, 0/*len*/, "SSH-2.0-", 8);
    success = !libssh2_banner_set(ss->session, SvPV_nolen(sv_banner));
    SvREFCNT_dec(sv_banner);
    XSRETURN_IV(success);

void
net_ss_error(SSH2* ss, ...)
PREINIT:
    SV* errmsg;
    int errcode;
CODE:
    if (items == 3) {
        set_error(ss, SvIV(ST(1)), SvPV_nolen(ST(2)));
        XSRETURN_EMPTY;
    } else if(items != 1)
        croak("%s::error: too many arguments", class);

    /* if we have a local error, take it, else use libSSH2's value */
    if (ss->errcode != LIBSSH2_ERROR_NONE && ss->errmsg != NULL) {
        errcode = ss->errcode;
        errmsg = SvREFCNT_inc(ss->errmsg);
    } else {
        char* errstr;
        int errlen;
        errcode = libssh2_session_last_error(
         ss->session, &errstr, &errlen, 0/*want_buf*/);
        errmsg = errstr ? newSVpvn(errstr, errlen) : NULL;
    }

    if (errcode == LIBSSH2_ERROR_NONE && errmsg == NULL)
        XSRETURN_EMPTY;
    switch (GIMME_V) {
    case G_SCALAR:
        XSRETURN_IV(errcode);
    case G_ARRAY: {
        SV* code;
        EXTEND(SP, 3);
        ST(0) = sv_2mortal(newSViv(errcode));
        if (errcode < 0) {
            code = (-errcode < countof(xs_libssh2_error)) ? 
             newSVpvf("LIBSSH2_ERROR_%s", xs_libssh2_error[-errcode]) :
             newSVpvf("LIBSSH2_ERROR_UNKNOWN(%d)", errcode);
        } else if(errcode > 0)
            code = newSVpv(Strerror(errcode), 0);
        else
            code = newSVpvn("", 0);  /* possibly set via set_error */
        ST(1) = sv_2mortal(code);
        ST(2) = sv_2mortal(errmsg);
        XSRETURN(3);
    }
    }

void
net_ss_method(SSH2* ss, SV* method_type, ...)
PREINIT:
    IV type;
    int i;
    SV* prefs;
    STRLEN len;
PPCODE:
    clear_error(ss);
    if (!iv_constant_sv("LIBSSH2_METHOD_", method_type, &type))
        croak("%s::method: unknown method type: %s",
         class, SvPV_nolen(method_type));
    
    /* if there are no other parameters, return the current value */
    if (items <= 2) {
        const char *method = libssh2_session_methods(ss->session, (int)type);
        if (!method)
            XSRETURN_EMPTY;
        XSRETURN_PV(method);
    }
        
    /* accept prefs as a string or multiple strings, joining with "," */
    prefs = newSVpvn("", 0);
    for (i = 2; i < items; ++i) {
        const char* pv_pref;
        if (i > 2)
            sv_catpvn(prefs, ",", 1);
        pv_pref = SvPV(ST(i), len);
        sv_catpvn(prefs, pv_pref, len);
    }

    /* call and clean up */
    i = libssh2_session_method_pref(ss->session,
     (int)type, SvPV_nolen(prefs));
    SvREFCNT_dec(prefs);
    XSRETURN_IV(!i);

#if LIBSSH2_VERSION_NUM >= 0x010200

void
net_ss_flag(SSH2* ss, SV* flag, int value)
PREINIT:
    IV flag_iv;
    int success;
PPCODE:
    clear_error(ss);
    if (!iv_constant_sv("LIBSSH2_FLAG_", flag, &flag_iv))
        croak("%s::method: unknown flag: %s", class, SvPV_nolen(flag));
    success = libssh2_session_flag(ss->session, (int)flag_iv, value);
    XSRETURN_IV(!success);

#else

void
net_ss_flag(SSH2* ss, SV* flag, int value)
CODE:
    croak("libssh2 version 1.2 or higher required for flag support");

#endif

void
net_ss_callback(SSH2* ss, SV* type, SV* callback = NULL)
PREINIT:
    IV i_type;
CODE:
    clear_error(ss);
    if (callback && !SvOK(callback))
        callback = NULL;
    if (callback && !(SvROK(callback) && SvTYPE(SvRV(callback)) == SVt_PVCV))
        croak("%s::callback: callback must be CODE ref", class);
    if (!iv_constant_sv("LIBSSH2_CALLBACK_", type, &i_type))
        croak("%s::callback: invalid callback type: %s",
         class, SvPV_nolen(callback));
    if (i_type < 0 || i_type >= countof(msg_cb))
        croak("%s::callback: don't know how to handle: %s",
         class, SvPV_nolen(callback));

    ss->sv_ss = SvRV(ST(0));  /* don't keep a reference, just store it */
    SvREFCNT_dec(ss->rgsv_cb[i_type]);
    libssh2_session_callback_set(ss->session,
     i_type, callback ? cb_as_void_ptr(msg_cb[i_type]) : NULL);
    SvREFCNT_inc(callback);
    ss->rgsv_cb[i_type] = callback;
    XSRETURN_IV(1);

void
net_ss__startup(SSH2* ss, int socket, SV *store)
PREINIT:
    int success;
CODE:
    clear_error(ss);
    success = !libssh2_session_startup(ss->session, socket);
    if (success && store) {
        ss->socket = SvREFCNT_inc(SvRV(store));
    }
    XSRETURN_IV(success);

SV *
net_ss_sock(SSH2* ss)
CODE:
    if (ss->socket) {
        RETVAL = newRV_inc((SV *)ss->socket);
    } else {
        RETVAL = &PL_sv_undef;
    }
OUTPUT:
    RETVAL

void
net_ss_disconnect(SSH2* ss, const char* description = "", \
 int reason = SSH_DISCONNECT_BY_APPLICATION, const char *lang = "")
CODE:
    clear_error(ss);
    XSRETURN_IV(!libssh2_session_disconnect_ex(
     ss->session, reason, description, lang));

void
net_ss_hostkey_hash(SSH2* ss, SV* hash_type)
PREINIT:
    IV type;
    const char* hash;
    static STRLEN rglen[] = { 16/*MD5*/, 20/*SHA1*/ };
PPCODE:
    clear_error(ss);
    if (!iv_constant_sv("LIBSSH2_HOSTKEY_HASH_", hash_type, &type) ||
     type < 1 || type > countof(rglen)) {
        croak("%s::hostkey: unknown hostkey hash: %s",
         class, SvPV_nolen(hash_type));
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

void
net_ss_auth_list(SSH2* ss, SV* username = NULL)
PREINIT:
    const char* pv_username = NULL;
    char* auth;
    STRLEN len_username = 0;
    int count = 1;
PPCODE:
    clear_error(ss);
    if (username && SvPOK(username))
        pv_username = SvPV(username, len_username);
    auth = libssh2_userauth_list(ss->session, pv_username, len_username);
    if (!auth)
        XSRETURN_EMPTY;
    if (GIMME_V == G_ARRAY)
        count = split_comma(sp, auth);
    else
        PUSHs(sv_2mortal(newSVpv(auth, 0)));
    /* Safefree(auth); this causes a double-free segfault */
    XSRETURN(count);

void
net_ss_auth_ok(SSH2* ss)
CODE:
    clear_error(ss);
    XSRETURN_IV(libssh2_userauth_authenticated(ss->session));

void
net_ss_auth_password(SSH2* ss, SV* username, SV* password = NULL, \
 SV* callback = NULL)
PREINIT:
    STRLEN len_username, len_password;
    const char* pv_username, * pv_password;
    int i;
CODE:
    clear_error(ss);
    if (callback && SvOK(callback) &&
     !(SvROK(callback) && SvTYPE(SvRV(callback)) == SVt_PVCV))
        croak("%s::auth_password: callback must be CODE ref", class);
    pv_username = SvPV(username, len_username);

    /* if we don't have a password, try for an unauthenticated login */
    if (!password || !SvPOK(password)) {
        char* auth = libssh2_userauth_list(ss->session,
         pv_username, len_username);
        /* This causes a double free segfault
         * Safefree(auth);
         */
        XSRETURN_IV(!auth && libssh2_userauth_authenticated(ss->session));
    }

    /* if we have a callback, setup its parameters */
    if (callback) {
        AV* args = (AV*)sv_2mortal((SV*)newAV());
        av_store(args, 0, newSVsv(callback));
        av_store(args, 1, newSVsv(ST(0)));
        av_store(args, 2, newSVsv(username));
        ss->sv_tmp = (SV*)args;
    }

    pv_password = SvPV(password, len_password);
    XSRETURN_IV(!libssh2_userauth_password_ex(ss->session, pv_username,
     len_username, pv_password, len_password,
     callback ? cb_password_change_callback : NULL));

    if (callback)
        ss->sv_tmp = NULL;

#if LIBSSH2_VERSION_NUM >= 0x010203

SV *
net_ss_auth_agent(SSH2* ss, const char* username)
PREINIT:
    LIBSSH2_AGENT *agent;
    int old_blocking;
CODE:
    RETVAL = &PL_sv_no;
    clear_error(ss);
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
            libssh2_agent_disconnect(agent);
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

void
net_ss_auth_publickey(SSH2* ss, SV* username, SV* publickey, \
 const char* privatekey, SV* passphrase = NULL)
PREINIT:
    const char* pv_username;
    STRLEN len_username;
CODE:
    clear_error(ss);
    pv_username = SvPV(username, len_username);

    XSRETURN_IV(!libssh2_userauth_publickey_fromfile_ex(ss->session,
     pv_username, len_username, default_string(publickey), privatekey,
     default_string(passphrase)));

void
net_ss_auth_hostbased(SSH2* ss, SV* username, const char* publickey, \
 const char* privatekey, SV* hostname, SV* local_username = NULL, \
 SV* passphrase = NULL)
PREINIT:
    const char* pv_username, * pv_hostname, * pv_local_username;
    STRLEN len_username, len_hostname, len_local_username;
CODE:
    clear_error(ss);
    pv_username = SvPV(username, len_username);
    pv_hostname = SvPV(hostname, len_hostname);

    if (!local_username || !SvPOK(local_username)) {
        pv_local_username = pv_username;
        len_local_username = len_username;
    } else
        pv_local_username = SvPV(local_username, len_local_username);

    XSRETURN_IV(!libssh2_userauth_hostbased_fromfile_ex(ss->session,
     pv_username, len_username, publickey, privatekey,
     default_string(passphrase),
     pv_hostname, len_hostname, pv_local_username, len_local_username));

void
net_ss_auth_keyboard(SSH2* ss, SV* username, SV* password = NULL)
PREINIT:
    const char* pv_username;
    STRLEN len_username;
    int success;
CODE:
    clear_error(ss);
    pv_username = SvPV(username, len_username);

    /* we either have a password, or a reference to a callback */
    if (password && SvPOK(password)) {
        ss->sv_tmp = password;
        success = !libssh2_userauth_keyboard_interactive_ex(
         ss->session, pv_username, len_username, cb_kbdint_response_password);
        ss->sv_tmp = NULL;
        XSRETURN_IV(success);
    }

    /* alright, reference to callback it is */
    if (!password || !SvOK(password))
        password = sv_2mortal(newRV_noinc((SV*)get_cv(
         "Net::SSH2::_cb_kbdint_response_default", 0/*create*/)));
    if (!SvROK(password) || SvTYPE(SvRV(password)) != SVt_PVCV)
        croak("%s::auth_keyboard requires password or CODE ref", class);

    /* set up parameters for callback */
    {
        SV* rgsv[3];  /* callback, params... */
        int i;

			 	rgsv[0] = password;
				rgsv[1] = ST(0);
				rgsv[2] = username;

        for (i = 0; i < countof(rgsv); ++i)
            SvREFCNT_inc(rgsv[i]);
        ss->sv_tmp = (SV*)av_make(countof(rgsv), rgsv);
    }
    SvREFCNT_inc(SvRV(password));

    success = !libssh2_userauth_keyboard_interactive_ex(
     ss->session, pv_username, len_username, cb_kbdint_response_callback);

    SvREFCNT_dec(SvRV(password));
    SvREFCNT_dec(ss->sv_tmp);
    ss->sv_tmp = NULL;
    XSRETURN_IV(success);

#if LIBSSH2_VERSION_NUM >= 0x010205

void
net_ss_keepalive_config(SSH2 *ss, int want_reply, unsigned int interval)
CODE:
    libssh2_keepalive_config(ss->session, want_reply, interval);

void
net_ss_keepalive_send(SSH2 *ss)
PREINIT:
    int success;
    int seconds_to_next;
PPCODE:
    success = libssh2_keepalive_send(ss->session, &seconds_to_next);
    if (success == LIBSSH2_ERROR_NONE)
        XSRETURN_IV(seconds_to_next);
    else
        XSRETURN_EMPTY;

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
net_ss_channel(SSH2* ss, SV* channel_type = NULL, \
 int window_size = LIBSSH2_CHANNEL_WINDOW_DEFAULT, \
 int packet_size = LIBSSH2_CHANNEL_PACKET_DEFAULT)
PREINIT:
    const char* pv_channel_type;
    STRLEN len_channel_type;
CODE:
    clear_error(ss);
    if (channel_type)
        pv_channel_type = SvPV(channel_type, len_channel_type);
    else {
        pv_channel_type = "session";
        len_channel_type = 7;
    }

    NEW_CHANNEL(libssh2_channel_open_ex(ss->session,
     pv_channel_type, len_channel_type, window_size, packet_size,
     NULL/*message*/, 0/*message_len*/));
OUTPUT:
    RETVAL

SSH2_CHANNEL*
net_ss__scp_get(SSH2* ss, const char* path, HV* stat = NULL)
PREINIT:
    struct stat st;
CODE:
    clear_error(ss);
    NEW_CHANNEL(libssh2_scp_recv(ss->session, path, &st));
    if (stat) {
        hv_clear(stat);
        hv_store(stat, "mode",  4, newSVuv(st.st_mode),  0/*hash*/);
        hv_store(stat, "uid",   3, newSVuv(st.st_uid),   0/*hash*/);
        hv_store(stat, "gid",   3, newSVuv(st.st_gid),   0/*hash*/);
        hv_store(stat, "size",  4, newSVuv(st.st_size),  0/*hash*/);
        hv_store(stat, "atime", 5, newSVuv((time_t)st.st_atime), 0/*hash*/);
        hv_store(stat, "mtime", 5, newSViv((time_t)st.st_mtime), 0/*hash*/);
    }
OUTPUT:
    RETVAL

SSH2_CHANNEL*
net_ss__scp_put(SSH2* ss, const char* path, int mode, size_t size, \
    long mtime = 0, long atime = 0)
CODE:
    clear_error(ss);
    NEW_CHANNEL(libssh2_scp_send_ex(ss->session,
     path, mode, size, mtime, atime));
OUTPUT:
    RETVAL

SSH2_CHANNEL*
net_ss_tcpip(SSH2* ss, const char* host, int port, \
 const char* shost = NULL, int sport = 0)
CODE:
    if (!shost)
        shost = "127.0.0.1";
    if (!sport)
        sport = 22;
    NEW_CHANNEL(libssh2_channel_direct_tcpip_ex(ss->session,
     (char*)host, port, (char*)shost, sport));
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
    clear_error(ss);
    count = av_len(event) + 1;
    debug("%s::poll: timeout = %d, array[%d]\n", class, timeout, count);
    if (!count)  /* some architectures return null for malloc(0) */
        XSRETURN_IV(0);

    New(0, pollfd, count, LIBSSH2_POLLFD);

    if (!pollfd) {
        set_error(ss, 0, "out of memory allocating pollfd structures");
        XSRETURN_EMPTY;
    }
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
             class, i, SvPV_nolen(*handle));
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
    clear_error(ss);
    NEW_SFTP(libssh2_sftp_init(ss->session));
OUTPUT:
    RETVAL

SSH2_PUBLICKEY*
net_ss_public_key(SSH2* ss)
CODE:
    clear_error(ss);
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
    clear_error(ch->ss);
    libssh2_channel_free(ch->channel);
    SvREFCNT_dec(ch->sv_ss);
    Safefree(ch);

void
net_ch_session(SSH2_CHANNEL* ch)
CODE:
    ST(0) = sv_2mortal(newRV_inc(ch->sv_ss));
    XSRETURN(1);

void
net_ch_setenv(SSH2_CHANNEL* ch, ...)
PREINIT:
    int i, success = 0;
    const char* pv_key, * pv_value;
    STRLEN len_key, len_value;
CODE:
    clear_error(ch->ss);
    for (i = 1; i < items; i += 2) {
        if (i + 1 == items)
            croak("%s::setenv: key without value", class);
        pv_key = SvPV(ST(i), len_key);
        pv_value = SvPV(ST(i + 1), len_value);
        success += !libssh2_channel_setenv_ex(ch->channel,
         (char*)pv_key, len_key, (char*)pv_value, len_value);
    }
    XSRETURN_IV(success);

#if LIBSSH2_VERSION_NUM >= 0x010208

SV*
net_ch_exit_signal(SSH2_CHANNEL* ch)
PREINIT:
    char *exitsignal = NULL;  
CODE:
    clear_error(ch->ss);
    RETVAL;
    libssh2_channel_get_exit_signal(ch->channel, &exitsignal,
        NULL, NULL, NULL, NULL, NULL);
    if (exitsignal) {
        RETVAL = newSVpv(exitsignal, 0);
        libssh2_free(ch->ss->session, exitsignal);
    }
    else
        RETVAL = &PL_sv_undef;
OUTPUT:
    RETVAL

#else

void
net_ch_exit_signal(SSH2_CHANNEL* ch)
CODE:
    croak("libssh2 version 1.2.8 or higher required for exit_signal support");

#endif

void
net_ch_blocking(SSH2_CHANNEL* ch, SV* blocking)
CODE:
    clear_error(ch->ss);
    libssh2_channel_set_blocking(ch->channel, SvTRUE(blocking));
    XSRETURN_IV(1);

void
net_ch_eof(SSH2_CHANNEL* ch)
CODE:
   clear_error(ch->ss);
   XSRETURN_IV(libssh2_channel_eof(ch->channel));

void
net_ch_send_eof(SSH2_CHANNEL* ch)
CODE:
    clear_error(ch->ss);
    XSRETURN_IV(!libssh2_channel_send_eof(ch->channel));

void
net_ch_close(SSH2_CHANNEL* ch)
CODE:
    clear_error(ch->ss);
    XSRETURN_IV(!libssh2_channel_close(ch->channel));

void
net_ch_wait_closed(SSH2_CHANNEL* ch)
CODE:
    clear_error(ch->ss);
    XSRETURN_IV(!libssh2_channel_wait_closed(ch->channel));

void
net_ch_exit_status(SSH2_CHANNEL* ch)
CODE:
    clear_error(ch->ss);
    XSRETURN_IV(libssh2_channel_get_exit_status(ch->channel));

#if LIBSSH2_VERSION_MAJOR >= 1

void
net_ch_pty(SSH2_CHANNEL* ch, SV* terminal, SV* modes = NULL, \
 int width = 0, int height = 0)
PREINIT:
    const char* pv_terminal, * pv_modes = NULL;
    STRLEN len_terminal, len_modes = 0;
    int width_px = LIBSSH2_TERM_WIDTH_PX, height_px = LIBSSH2_TERM_HEIGHT_PX;
CODE:
    pv_terminal = SvPV(terminal, len_terminal);
    if (modes && SvPOK(modes))
        pv_modes = SvPV(modes, len_modes);

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

    XSRETURN_IV(!libssh2_channel_request_pty_ex(ch->channel,
     (char*)pv_terminal, len_terminal, (char*)pv_modes, len_modes,
     width, height, width_px, height_px));

void
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

    XSRETURN_IV(!libssh2_channel_request_pty_size_ex(ch->channel,
     width, height, width_px, height_px));

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

void
net_ch_process(SSH2_CHANNEL* ch, SV* request, SV* message = NULL)
PREINIT:
    const char* pv_request, * pv_message = NULL;
    STRLEN len_request, len_message = 0;
CODE:
    pv_request = SvPV(request, len_request);
    if (message && SvPOK(message))
        pv_message = SvPV(message, len_message);

    XSRETURN_IV(!libssh2_channel_process_startup(ch->channel,
     pv_request, len_request, pv_message, len_message));

void
net_ch_ext_data(SSH2_CHANNEL* ch, SV* mode)
PREINIT:
    IV i_mode;
CODE:
    if (!iv_constant_sv("LIBSSH2_CHANNEL_EXTENDED_DATA_", mode, &i_mode))
        croak("%s::ext_data: unknown extended data mode: %s",
         class, SvPV_nolen(mode));
    libssh2_channel_handle_extended_data(ch->channel, i_mode);
    XSRETURN_IV(1);

void
net_ch_read(SSH2_CHANNEL* ch, SV* buffer, size_t size, SV *ext = &PL_sv_undef)
PREINIT:
    char* pv_buffer;
    int count, total = 0;
CODE:
    debug("%s::read(size = %d, ext = %d)\n", class, size, SvTRUE(ext));
    clear_error(ch->ss);
    SvPOK_on(buffer);
    pv_buffer = sv_grow(buffer, size + 1/*NUL*/);  /* force PV */

    again:
    count = libssh2_channel_read_ex(ch->channel, XLATEXT, pv_buffer, size);
    debug("- read %d bytes\n", count);

    if (count < 0) {
        if (!total) {
            SvCUR_set(buffer, 0);
            XSRETURN_EMPTY;
        }
        count = 0;
    }

    total += count;

    if (count > 0 && (unsigned)count < size &&
        libssh2_session_get_blocking(ch->ss->session)) {

        pv_buffer += count;
        size -= count;
        goto again;
    }

    pv_buffer[count] = '\0';
    SvCUR_set(buffer, total);
    debug("- read %d total\n", total);
    XSRETURN_IV(total);

void
net_ch_write(SSH2_CHANNEL* ch, SV* buffer, SV *ext = &PL_sv_undef)
PREINIT:
    const char* pv_buffer;
    STRLEN len_buffer;
    int count;
CODE:
    clear_error(ch->ss);
    pv_buffer = SvPV(buffer, len_buffer);
    do {
        count = libssh2_channel_write_ex(ch->channel, XLATEXT,
         pv_buffer, len_buffer);
        if (count < 0 && LIBSSH2_ERROR_EAGAIN != count)
            XSRETURN_EMPTY;
        if (LIBSSH2_ERROR_EAGAIN == count
                && libssh2_session_get_blocking(ch->ss->session) == 0)
            XSRETURN_IV(LIBSSH2_ERROR_EAGAIN);
    } while (LIBSSH2_ERROR_EAGAIN == count);
    XSRETURN_IV(count);

#if LIBSSH2_VERSION_NUM >= 0x010100

void
net_ch_receive_window_adjust(SSH2_CHANNEL *ch, unsigned long adjustment, SV *force = &PL_sv_undef)
PREINIT:
    unsigned int new_size;
PPCODE:
    if (libssh2_channel_receive_window_adjust2(ch->channel, adjustment,
                                               SvTRUE(force), &new_size) == LIBSSH2_ERROR_NONE) {
        XPUSHs(sv_2mortal(newSVuv(new_size)));
        XSRETURN(1);
    }
    else
        XSRETURN_EMPTY;

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

void
net_ch_flush(SSH2_CHANNEL* ch, SV *ext = &PL_sv_undef)
PREINIT:
    int count;
CODE:
    clear_error(ch->ss);
    count = libssh2_channel_flush_ex(ch->channel, XLATEXT);
    if (count < 0)
        XSRETURN_EMPTY;
    XSRETURN_IV(count);

#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::Listener    PREFIX = net_ls_
PROTOTYPES: DISABLE

#define class "Net::SSH2::Listener"

void
net_ls_DESTROY(SSH2_LISTENER* ls)
CODE:
    debug("%s::DESTROY\n", class);
    clear_error(ls->ss);
    libssh2_channel_forward_cancel(ls->listener);
    SvREFCNT_dec(ls->sv_ss);
    Safefree(ls);

SSH2_CHANNEL*
net_ls_accept(SSH2_LISTENER* ls)
PREINIT:
    SSH2* ss;
CODE:
    clear_error(ss = ls->ss);
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
    clear_error(sf->ss);
    libssh2_sftp_shutdown(sf->sftp);
    debug("%s::DESTROY freeing session\n", class);
    SvREFCNT_dec(sf->sv_ss);
    Safefree(sf);

void
net_sf_session(SSH2_SFTP* sf)
CODE:
    ST(0) = sv_2mortal(newRV_inc(sf->sv_ss));
    XSRETURN(1);

void
net_sf_error(SSH2_SFTP* sf)
PREINIT:
    unsigned long error;
CODE:
    error = libssh2_sftp_last_error(sf->sftp);
    switch (GIMME_V) {
    case G_SCALAR:
        XSRETURN_UV(error);
    case G_ARRAY:
        EXTEND(SP, 2);
        ST(0) = sv_2mortal(newSVuv(error));
        if (error < countof(sftp_error))
            ST(1) = sv_2mortal(newSVpvf("SSH_FX_%s", sftp_error[error]));
        else
            ST(1) = sv_2mortal(newSVpvf("SSH_FX_UNKNOWN(%lu)", error));
        XSRETURN(2);
    }

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
    clear_error(sf->ss);
    pv_file = SvPV(file, len_file);
    
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
    clear_error(sf->ss);
    pv_dir = SvPV(dir, len_dir);
    NEW_DIR(libssh2_sftp_open_ex(sf->sftp, (char*)pv_dir, len_dir,
     0/*flags*/, 0/*mode*/, LIBSSH2_SFTP_OPENDIR));
OUTPUT:
    RETVAL

void
net_sf_unlink(SSH2_SFTP* sf, SV* file)
PREINIT:
    const char* pv_file;
    STRLEN len_file;
CODE:
    clear_error(sf->ss);
    pv_file = SvPV(file, len_file);
    XSRETURN_IV(!libssh2_sftp_unlink_ex(sf->sftp, (char*)pv_file, len_file));

void
net_sf_rename(SSH2_SFTP* sf, SV* old, SV* new, \
 long flags = LIBSSH2_SFTP_RENAME_OVERWRITE | \
              LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE)
PREINIT:
    const char* pv_old, * pv_new;
    STRLEN len_old, len_new;
CODE:
    clear_error(sf->ss);
    pv_old = SvPV(old, len_old);
    pv_new = SvPV(new, len_new);
    XSRETURN_IV(!libssh2_sftp_rename_ex(sf->sftp,
     (char*)pv_old, len_old, (char*)pv_new, len_new, flags));

void
net_sf_mkdir(SSH2_SFTP* sf, SV* dir, int mode = 0777)
PREINIT:
    const char* pv_dir;
    STRLEN len_dir;
CODE:
    clear_error(sf->ss);
    pv_dir = SvPV(dir, len_dir);
    XSRETURN_IV(!libssh2_sftp_mkdir_ex(sf->sftp, (char*)pv_dir, len_dir, mode));

void
net_sf_rmdir(SSH2_SFTP* sf, SV* dir)
PREINIT:
    const char* pv_dir;
    STRLEN len_dir;
CODE:
    clear_error(sf->ss);
    pv_dir = SvPV(dir, len_dir);
    XSRETURN_IV(!libssh2_sftp_rmdir_ex(sf->sftp, (char*)pv_dir, len_dir));

void
net_sf_stat(SSH2_SFTP* sf, SV* path, int follow = 1)
PREINIT:
    const char* pv_path;
    STRLEN len_path;
    int success;
    LIBSSH2_SFTP_ATTRIBUTES attrs;
PPCODE:
    clear_error(sf->ss);
    pv_path = SvPV(path, len_path);
    success = !libssh2_sftp_stat_ex(sf->sftp, (char*)pv_path, len_path,
     follow ? LIBSSH2_SFTP_STAT : LIBSSH2_SFTP_LSTAT, &attrs);
    if (!success)
        XSRETURN_EMPTY;
    XSRETURN_STAT_ATTRS(SvREFCNT_inc(path));

void
net_sf_setstat(SSH2_SFTP* sf, SV* path, ...)
PREINIT:
    const char* pv_path;
    STRLEN len_path;
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int i;
CODE:
    clear_error(sf->ss);
    pv_path = SvPV(path, len_path);
    Zero(&attrs, 1, LIBSSH2_SFTP_ATTRIBUTES);

    /* read key/value pairs; cf. hv_from_attrs */
    for (i = 2; i < items; i += 2) {
        const char* key = SvPV_nolen(ST(i));
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
    
    XSRETURN_IV(!libssh2_sftp_stat_ex(sf->sftp, (char*)pv_path, len_path,
     LIBSSH2_SFTP_SETSTAT, &attrs));

void
net_sf_symlink(SSH2_SFTP* sf, SV* path, SV* target)
PREINIT:
    const char* pv_path, * pv_target;
    STRLEN len_path, len_target;
CODE:
    clear_error(sf->ss);
    pv_path = SvPV(path, len_path);
    pv_target = SvPV(target, len_target);
    XSRETURN_IV(!libssh2_sftp_symlink_ex(sf->sftp,
     pv_path, len_path, (char*)pv_target, len_target, LIBSSH2_SFTP_SYMLINK));

void
net_sf_readlink(SSH2_SFTP* sf, SV* path)
PREINIT:
    SV* link;
    const char* pv_path;
    char* pv_link;
    STRLEN len_path;
    int count;
CODE:
    clear_error(sf->ss);
    pv_path = SvPV(path, len_path);
    link = newSV(MAXPATHLEN + 1);
    SvPOK_on(link);
    pv_link = SvPVX(link);

    count = libssh2_sftp_symlink_ex(sf->sftp,
     pv_path, len_path, pv_link, MAXPATHLEN, LIBSSH2_SFTP_READLINK);

    if (count < 0) {
        SvREFCNT_dec(link);
        XSRETURN_EMPTY;
    }
    pv_link[count] = '\0';
    SvCUR_set(link, count);
    ST(0) = sv_2mortal(link);
    XSRETURN(1);

void
net_sf_realpath(SSH2_SFTP* sf, SV* path)
PREINIT:
    SV* real;
    const char* pv_path;
    char* pv_real;
    STRLEN len_path;
    int count;
CODE:
    clear_error(sf->ss);
    pv_path = SvPV(path, len_path);
    real = newSV(MAXPATHLEN + 1);
    SvPOK_on(real);
    pv_real = SvPVX(real);

    count = libssh2_sftp_symlink_ex(sf->sftp,
     pv_path, len_path, pv_real, MAXPATHLEN, LIBSSH2_SFTP_REALPATH);

    if (count < 0) {
        SvREFCNT_dec(real);
        XSRETURN_EMPTY;
    }
    pv_real[count] = '\0';
    SvCUR_set(real, count);
    ST(0) = sv_2mortal(real);
    XSRETURN(1);

#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::File   PREFIX = net_fi_
PROTOTYPES: DISABLE

#define class "Net::SSH2::File"

void
net_fi_DESTROY(SSH2_FILE* fi)
CODE:
    debug("%s::DESTROY\n", class);
    clear_error(fi->sf->ss);
    libssh2_sftp_close_handle(fi->handle);
    SvREFCNT_dec(fi->sv_sf);
    Safefree(fi);

void
net_fi_read(SSH2_FILE* fi, SV* buffer, size_t size)
PREINIT:
    char* pv_buffer;
    int count;
CODE:
    clear_error(fi->sf->ss);
    SvPOK_on(buffer);
    pv_buffer = sv_grow(buffer, size + 1/*NUL*/);  /* force PV */
    pv_buffer[size] = '\0';

    count = libssh2_sftp_read(fi->handle, pv_buffer, size);
    if (count < 0) {
        SvCUR_set(buffer, 0);
        XSRETURN_EMPTY;
    }
    SvCUR_set(buffer, count);
    XSRETURN_IV(count);

void
net_fi_write(SSH2_FILE* fi, SV* buffer)
PREINIT:
    const char* pv_buffer;
    STRLEN len_buffer;
    ssize_t count;
CODE:
    clear_error(fi->sf->ss);
    pv_buffer = SvPV(buffer, len_buffer);
    count = libssh2_sftp_write(fi->handle, pv_buffer, len_buffer);
    if (count < 0)
        XSRETURN_EMPTY;
    XSRETURN_UV(count);    

void
net_fi_stat(SSH2_FILE* fi)
PREINIT:
    LIBSSH2_SFTP_ATTRIBUTES attrs;
PPCODE:
    clear_error(fi->sf->ss);
    if (libssh2_sftp_fstat(fi->handle, &attrs))
        XSRETURN_EMPTY;
    XSRETURN_STAT_ATTRS(NULL/*name*/);

void
net_fi_setstat(SSH2_FILE* fi, ...)
PREINIT:
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int i;
CODE:
    clear_error(fi->sf->ss);
    Zero(&attrs, 1, LIBSSH2_SFTP_ATTRIBUTES);

    /* read key/value pairs; cf. hv_from_attrs */
    for (i = 1; i < items; i += 2) {
        const char* key = SvPV_nolen(ST(i));
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
    
    XSRETURN_IV(!libssh2_sftp_fsetstat(fi->handle, &attrs));

void
net_fi_seek(SSH2_FILE* fi, size_t offset)
CODE:
    clear_error(fi->sf->ss);
    libssh2_sftp_seek(fi->handle, offset);
    XSRETURN(1);

void
net_fi_tell(SSH2_FILE* fi)
CODE:
    clear_error(fi->sf->ss);
    XSRETURN_UV(libssh2_sftp_tell(fi->handle));
        
#undef class


MODULE = Net::SSH2		PACKAGE = Net::SSH2::Dir   PREFIX = net_di_
PROTOTYPES: DISABLE

#define class "Net::SSH2::Dir"

void
net_di_DESTROY(SSH2_DIR* di)
CODE:
    debug("%s::DESTROY\n", class);
    clear_error(di->sf->ss);
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
    clear_error(di->sf->ss);
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
    clear_error(pk->ss);
    libssh2_publickey_shutdown(pk->pkey);
    SvREFCNT_dec(pk->sv_ss);
    Safefree(pk);

void
net_pk_add(SSH2_PUBLICKEY* pk, SV* name, SV* blob, int overwrite, ...)
PREINIT:
    int success;
    const char* pv_name, * pv_blob;
    STRLEN len_name, len_blob;
    unsigned long num_attrs, i;
    libssh2_publickey_attribute *attrs;
CODE:
    clear_error(pk->ss);
    pv_name = SvPV(name, len_name);
    pv_blob = SvPV(blob, len_blob);

    num_attrs = items - 4;
    New(0, attrs, num_attrs, libssh2_publickey_attribute);
    if (!attrs) {
        set_error(pk->ss, 0, "out of memory allocating attribute structures");
        XSRETURN_EMPTY;
    }
    for (i = 0; i < num_attrs; ++i) {
        HV* hv;
        SV** tmp;
        STRLEN len_tmp;

        if (!SvROK(ST(i + 4)) || SvTYPE(SvRV(ST(i + 4))) != SVt_PVHV)
            croak("%s::add: attribute %lu is not hash", class, i);
        hv = (HV*)SvRV(ST(i + 4));

        if (!(tmp = hv_fetch(hv, "name", 4, 0/*lval*/)) || !*tmp)
            croak("%s::add: attribute %lu missing name", class, i);
        attrs[i].name = SvPV(*tmp, len_tmp);
        attrs[i].name_len = len_tmp;

        if ((tmp = hv_fetch(hv, "value", 5, 0/*lval*/)) && *tmp) {
            attrs[i].value = SvPV(*tmp, len_tmp);
            attrs[i].value_len = len_tmp;
        } else
            attrs[i].value_len = 0;

        if ((tmp = hv_fetch(hv, "mandatory", 9, 0/*lval*/)) && *tmp)
            attrs[i].mandatory = (char)SvIV(*tmp);
        else
            attrs[i].mandatory = 0;
    }

    success = !libssh2_publickey_add_ex(pk->pkey,
     (const unsigned char *)pv_name, len_name,
     (const unsigned char *)pv_blob, len_blob, overwrite, num_attrs, attrs);

    Safefree(attrs);
    XSRETURN_IV(!success);
    
void
net_pk_remove(SSH2_PUBLICKEY* pk, SV* name, SV* blob)
PREINIT:
    const char* pv_name, * pv_blob;
    STRLEN len_name, len_blob;
CODE:
    clear_error(pk->ss);
    pv_name = SvPV(name, len_name);
    pv_blob = SvPV(blob, len_blob);
    XSRETURN_IV(!libssh2_publickey_remove_ex(pk->pkey,
     (const unsigned char *)pv_name, len_name,
     (const unsigned char *)pv_blob, len_blob));

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
    clear_error(kh->ss);
    libssh2_knownhost_free(kh->knownhosts);
    SvREFCNT_dec(kh->sv_ss);
    Safefree(kh);

void
net_kh_readfile(SSH2_KNOWNHOSTS *kh, const char *filename)
PREINIT:
    int n;
CODE:
    clear_error(kh->ss);
    n = libssh2_knownhost_readfile(kh->knownhosts, filename, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    if (n >= 0)
        XSRETURN_IV(n);
    else
        CROAK_LAST_ERROR(kh->ss, "readfile");

void
net_kh_writefile(SSH2_KNOWNHOSTS *kh, const char *filename)
PREINIT:
    int rc;
PPCODE:
    clear_error(kh->ss);
    rc = libssh2_knownhost_writefile(kh->knownhosts, filename, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    if (rc == LIBSSH2_ERROR_NONE) {
        XPUSHs(&PL_sv_yes);
        XSRETURN(1);
    }
    else
        CROAK_LAST_ERROR(kh->ss, "writefile");

void
net_kh_add(SSH2_KNOWNHOSTS *kh, const char *host, const char *salt, SV *key, SV *comment, int typemask)
PREINIT:
    int rc;
    STRLEN key_len, comment_len;
    const char *key_pv, *comment_pv;
CODE:
    clear_error(kh->ss);
    key_pv = SvPV_const(key, key_len);
    if (SvOK(comment))
        comment_pv = SvPV_const(comment, comment_len);
    else {
        comment_pv = NULL;
        comment_len = 0;
    }
#if LIBSSH2_VERSION_NUM >= 0x010205
    rc = libssh2_knownhost_addc(kh->knownhosts, host, salt, key_pv, key_len,
                                     comment_pv, comment_len, typemask, NULL);
#else
    if (SvOK(comment))
        croak("libssh2 version 1.2.5 is required to add keys with comments");
    rc = libssh2_knownhost_add(kh->knownhosts, host, salt, key_pv, key_len, typemask, NULL);
#endif
    if (rc == LIBSSH2_ERROR_NONE) {
        XPUSHs(&PL_sv_yes);
        XSRETURN(1);
    }
    else
        CROAK_LAST_ERROR(kh->ss, "add");

int
net_kh_check(SSH2_KNOWNHOSTS *kh, const char *host, SV *port, SV *key, int typemask)
PREINIT:
    STRLEN key_len;
    const char *key_pv;
    UV port_uv;
CODE:
    clear_error(kh->ss);
    key_pv = SvPV_const(key, key_len);
    port_uv = (SvOK(port) ? SvUV(port) : 0);
#if LIBSSH2_VERSION_NUM >= 0x010206
    RETVAL = libssh2_knownhost_checkp(kh->knownhosts, host, port_uv,
                                      key_pv, key_len, typemask, NULL);
#else
    if ((port != 0) && (port != 22))
        croak("libssh2 version 1.2.6 is required when using a custom TCP port");
    RETVAL = libssh2_knownhost_check(kh->knownhosts, host,
                                     key_pv, key_len, typemask, NULL);
#endif
OUTPUT:
    RETVAL

void
net_kh_readline(SSH2_KNOWNHOSTS *kh, SV *line)
PREINIT:
    int rc;
    STRLEN line_len;
    const char *line_pv;
PPCODE:
    line_pv = SvPV_const(line, line_len);
    rc = libssh2_knownhost_readline(kh->knownhosts, line_pv, line_len, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    if (rc == LIBSSH2_ERROR_NONE) {
        XPUSHs(&PL_sv_yes);
        XSRETURN(1);
    }
    else
        CROAK_LAST_ERROR(kh->ss, "readline");

void
net_kh_writeline(SSH2_KNOWNHOSTS *kh, const char *host, SV *port, SV *key, int typemask)
PREINIT:
    int rc;
    STRLEN key_len;
    const char *key_pv;
    UV port_uv;
    size_t line_len;
    STRLEN buffer_len;
    SV *buffer;
    struct libssh2_knownhost *entry = NULL;
PPCODE:
    clear_error(kh->ss);
    key_pv = SvPV_const(key, key_len);
    port_uv = (SvOK(port) ? SvUV(port) : 0);
#if LIBSSH2_VERSION_NUM >= 0x010206
    rc = libssh2_knownhost_checkp(kh->knownhosts, host, port_uv,
                                      key_pv, key_len, typemask, &entry);
#else
    if ((port != 0) && (port != 22))
        croak("libssh2 version 1.2.6 is required when using a custom TCP port");
    rc = libssh2_knownhost_check(kh->knownhosts, host,
                                 key_pv, key_len, typemask, &entry);
#endif
    if ((rc != LIBSSH2_KNOWNHOST_CHECK_MATCH) || !entry) {
#if LIBSSH2_VERSION_NUM >= 0x010403
        set_error(kh->ss, LIBSSH2_ERROR_KNOWN_HOSTS, "matching host key not found");        
#else
        set_error(kh->ss, LIBSSH2_ERROR_SOCKET_NONE, "matching host key not found");
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
                XPUSHs(buffer);
                XSRETURN(1);
            }

            if ((rc != LIBSSH2_ERROR_BUFFER_TOO_SMALL) ||
                (SvLEN(buffer) > 64 * 1024)) break;
                
            SvGROW(buffer, SvLEN(buffer) * 2);
        }
    }
    CROAK_LAST_ERROR(kh->ss, "writeline");



# /* TODO */
# libssh2_knownhost_del()
# libssh2_knownhost_get()
# libssh2_knownhost_writeline()

#endif

#undef class

# vim: set et ts=4:
