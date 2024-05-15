/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Configuration settings */
#define CONFIGURE_DEFINES "enable_async_push=no enable_comp_stub=no enable_crypto_ofb_cfb=yes enable_dco=no enable_debug=yes enable_dlopen=unknown enable_dlopen_self=unknown enable_dlopen_self_static=unknown enable_fast_install=needless enable_fragment=yes enable_iproute2=no enable_libtool_lock=yes enable_lz4=yes enable_lzo=yes enable_management=yes enable_pam_dlopen=no enable_pedantic=no enable_pkcs11=no enable_plugin_auth_pam=yes enable_plugin_down_root=yes enable_plugins=yes enable_port_share=yes enable_selinux=no enable_shared=yes enable_shared_with_static_runtimes=no enable_small=no enable_static=yes enable_strict=no enable_strict_options=no enable_systemd=no enable_werror=no enable_win32_dll=yes enable_wolfssl_options_h=yes enable_x509_alt_username=no with_aix_soname=aix with_crypto_library=openssl with_gnu_ld=yes with_mem_check=no with_openssl_engine=auto with_sysroot=no"

/* special build string */
/* #undef CONFIGURE_SPECIAL_BUILD */

/* Use memory debugging function in OpenSSL */
/* #undef CRYPTO_MDEBUG */

/* p11-kit proxy */
/* #undef DEFAULT_PKCS11_MODULE */

/* Use dmalloc memory debugging library */
/* #undef DMALLOC */

/* Enable async push */
/* #undef ENABLE_ASYNC_PUSH */

/* Enable compression stub capability */
/* #undef ENABLE_COMP_STUB */

/* Use mbed TLS library */
/* #undef ENABLE_CRYPTO_MBEDTLS */

/* Use wolfSSL openssl compatibility layer */
#define ENABLE_CRYPTO_OPENSSL 1

/* Use wolfSSL crypto library */
/* #undef ENABLE_CRYPTO_WOLFSSL */

/* Enable data channel offload for FreeBSD */
/* #undef ENABLE_DCO */

/* Enable debugging support */
#define ENABLE_DEBUG 1

/* We have persist tun capability */
#define ENABLE_FEATURE_TUN_PERSIST 1

/* Enable internal fragmentation support */
#define ENABLE_FRAGMENT 1

/* enable iproute2 support */
/* #undef ENABLE_IPROUTE */

/* Enable LZ4 compression library */
#define ENABLE_LZ4 1

/* Enable LZO compression library */
#define ENABLE_LZO 1

/* Enable management server capability */
#define ENABLE_MANAGEMENT 1

/* Enable OFB and CFB cipher modes */
#define ENABLE_OFB_CFB_MODE 1

/* Enable PKCS11 */
/* #undef ENABLE_PKCS11 */

/* Enable plug-in support */
/* #undef ENABLE_PLUGIN */

/* Enable TCP Server port sharing */
#define ENABLE_PORT_SHARE 1

/* SELinux support */
/* #undef ENABLE_SELINUX */

/* enable sitnl support */
#define ENABLE_SITNL 1

/* Enable smaller executable size */
/* #undef ENABLE_SMALL */

/* Enable systemd integration */
/* #undef ENABLE_SYSTEMD */

/* Enable --x509-username-field feature */
/* #undef ENABLE_X509ALTUSERNAME */

/* Include options.h from wolfSSL library */
/* #undef EXTERNAL_OPTS_OPENVPN */

/* Define to 1 if you have the `access' function. */
#define HAVE_ACCESS 1

/* Compiler supports anonymous unions */
#define HAVE_ANONYMOUS_UNION_SUPPORT /**/

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the `basename' function. */
#define HAVE_BASENAME 1

/* Define to 1 if you have the `chdir' function. */
#define HAVE_CHDIR 1

/* Define to 1 if you have the `chroot' function. */
#define HAVE_CHROOT 1

/* Define to 1 if you have the `chsize' function. */
/* #undef HAVE_CHSIZE */

/* struct cmsghdr needed for extended socket error support */
#define HAVE_CMSGHDR 1

/* extra version available in config-version.h */
/* #undef HAVE_CONFIG_VERSION_H */

/* Use mbedtls_ctr_drbg_update_ret from mbed TLS */
/* #undef HAVE_CTR_DRBG_UPDATE_RET */

/* Define to 1 if you have the `daemon' function. */
#define HAVE_DAEMON 1

/* Define to 1 if you have the declaration of `SIGHUP', and to 0 if you don't.
   */
#define HAVE_DECL_SIGHUP 1

/* Define to 1 if you have the declaration of `SIGINT', and to 0 if you don't.
   */
#define HAVE_DECL_SIGINT 1

/* Define to 1 if you have the declaration of `SIGTERM', and to 0 if you
   don't. */
#define HAVE_DECL_SIGTERM 1

/* Define to 1 if you have the declaration of `SIGUSR1', and to 0 if you
   don't. */
#define HAVE_DECL_SIGUSR1 1

/* Define to 1 if you have the declaration of `SIGUSR2', and to 0 if you
   don't. */
#define HAVE_DECL_SIGUSR2 1

/* Define to 1 if you have the declaration of `SO_MARK', and to 0 if you
   don't. */
#define HAVE_DECL_SO_MARK 1

/* Define to 1 if you have the declaration of `TUNSETPERSIST', and to 0 if you
   don't. */
#define HAVE_DECL_TUNSETPERSIST 1

/* Define to 1 if you have the `dirname' function. */
#define HAVE_DIRNAME 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <dmalloc.h> header file. */
/* #undef HAVE_DMALLOC_H */

/* Define to 1 if you have the `dup' function. */
#define HAVE_DUP 1

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the `ENGINE_load_builtin_engines' function. */
/* #undef HAVE_ENGINE_LOAD_BUILTIN_ENGINES */

/* Define to 1 if you have the `ENGINE_register_all_complete' function. */
/* #undef HAVE_ENGINE_REGISTER_ALL_COMPLETE */

/* Define to 1 if you have the `epoll_create' function. */
#define HAVE_EPOLL_CREATE 1

/* Define to 1 if you have the <err.h> header file. */
#define HAVE_ERR_H 1

/* Define to 1 if you have the `execve' function. */
#define HAVE_EXECVE 1

/* Crypto library supports keying material exporter */
#define HAVE_EXPORT_KEYING_MATERIAL 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `flock' function. */
#define HAVE_FLOCK 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define to 1 if you have the `getgrnam' function. */
#define HAVE_GETGRNAM 1

/* Define to 1 if you have the `getpeereid' function. */
/* #undef HAVE_GETPEEREID */

/* Define to 1 if you have the `getpwnam' function. */
#define HAVE_GETPWNAM 1

/* Define to 1 if you have the `getrlimit' function. */
#define HAVE_GETRLIMIT 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if the system has the type `in_addr_t'. */
#define HAVE_IN_ADDR_T 1

/* struct in_pktinfo needed for IP_PKTINFO support */
#define HAVE_IN_PKTINFO 1

/* Define to 1 if the system has the type `in_port_t'. */
#define HAVE_IN_PORT_T 1

/* Define to 1 if you have the <io.h> header file. */
/* #undef HAVE_IO_H */

/* struct iphdr needed for IPv6 support */
#define HAVE_IPHDR 1

/* struct in_pktinfo.ipi_spec_dst needed for IP_PKTINFO support */
#define HAVE_IPI_SPEC_DST 1

/* Enable libcap-ng support */
// #define HAVE_LIBCAPNG 1

/* Define to 1 if you have the <libgen.h> header file. */
#define HAVE_LIBGEN_H 1

/* Define to 1 if you have the `lz4' library (-llz4). */
#define HAVE_LIBLZ4 1

/* Define to 1 if you have the `wolfssl' library (-lwolfssl). */
/* #undef HAVE_LIBWOLFSSL */

/* Define to 1 if you have the <linux/errqueue.h> header file. */
#define HAVE_LINUX_ERRQUEUE_H 1

/* Define to 1 if you have the <linux/if_tun.h> header file. */
#define HAVE_LINUX_IF_TUN_H 1

/* Define to 1 if you have the <linux/sockios.h> header file. */
#define HAVE_LINUX_SOCKIOS_H 1

/* Define to 1 if you have the <linux/types.h> header file. */
#define HAVE_LINUX_TYPES_H 1

/* Define to 1 if you have the <lz4.h> header file. */
/* #undef HAVE_LZ4_H */

/* Define to 1 if you have the <lzo1x.h> header file. */
/* #undef HAVE_LZO1X_H */

/* Define to 1 if you have the <lzoutil.h> header file. */
/* #undef HAVE_LZOUTIL_H */

/* Define to 1 if you have the <lzo/lzo1x.h> header file. */
#define HAVE_LZO_LZO1X_H 1

/* Define to 1 if you have the <lzo/lzoutil.h> header file. */
#define HAVE_LZO_LZOUTIL_H 1

/* Define to 1 if you have the `mbedtls_cipher_check_tag' function. */
/* #undef HAVE_MBEDTLS_CIPHER_CHECK_TAG */

/* Define to 1 if you have the `mbedtls_cipher_write_tag' function. */
/* #undef HAVE_MBEDTLS_CIPHER_WRITE_TAG */

/* Define to 1 if you have the <minix/config.h> header file. */
/* #undef HAVE_MINIX_CONFIG_H */

/* Define to 1 if you have the `mlockall' function. */
#define HAVE_MLOCKALL 1

/* struct msghdr needed for extended socket error support */
#define HAVE_MSGHDR 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/ip.h> header file. */
#define HAVE_NETINET_IP_H 1

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#define HAVE_NETINET_TCP_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* Define to 1 if you have the <net/if_ovpn.h> header file. */
/* #undef HAVE_NET_IF_OVPN_H */

/* Define to 1 if you have the <net/if_tun.h> header file. */
/* #undef HAVE_NET_IF_TUN_H */

/* Define to 1 if you have the <net/if_utun.h> header file. */
/* #undef HAVE_NET_IF_UTUN_H */

/* Define to 1 if you have the <net/tun/if_tun.h> header file. */
/* #undef HAVE_NET_TUN_IF_TUN_H */

/* Define to 1 if you have the `nice' function. */
#define HAVE_NICE 1

/* Define to 1 if you have the `openlog' function. */
#define HAVE_OPENLOG 1

/* OpenSSL engine support available */
/* #undef HAVE_OPENSSL_ENGINE */

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `readv' function. */
#define HAVE_READV 1

/* Define to 1 if you have the `recvmsg' function. */
#define HAVE_RECVMSG 1

/* Define to 1 if you have the <resolv.h> header file. */
#define HAVE_RESOLV_H 1

/* sa_family_t, needed to hold AF_* info */
#define HAVE_SA_FAMILY_T 1

/* Define to 1 if you have the `sd_booted' function. */
/* #undef HAVE_SD_BOOTED */

/* Define to 1 if you have the `sendmsg' function. */
#define HAVE_SENDMSG 1

/* Define to 1 if you have the `setgid' function. */
#define HAVE_SETGID 1

/* Define to 1 if you have the `setgroups' function. */
#define HAVE_SETGROUPS 1

/* Define to 1 if you have the `setsid' function. */
#define HAVE_SETSID 1

/* Define to 1 if you have the `setuid' function. */
#define HAVE_SETUID 1

/* Define to 1 if you have the `SSL_CTX_new' function. */
#define HAVE_SSL_CTX_NEW 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <stropts.h> header file. */
/* #undef HAVE_STROPTS_H */

/* Define to 1 if you have the `strsep' function. */
#define HAVE_STRSEP 1

/* Define to 1 if you have the `syslog' function. */
#define HAVE_SYSLOG 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the `system' function. */
#define HAVE_SYSTEM 1

/* Define to 1 if you have the <systemd/sd-daemon.h> header file. */
/* #undef HAVE_SYSTEMD_SD_DAEMON_H */

/* Define to 1 if you have the <sys/epoll.h> header file. */
#define HAVE_SYS_EPOLL_H 1

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/inotify.h> header file. */
/* #undef HAVE_SYS_INOTIFY_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/kern_control.h> header file. */
/* #undef HAVE_SYS_KERN_CONTROL_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <tap-windows.h> header file. */
/* #undef HAVE_TAP_WINDOWS_H */

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the `time' function. */
#define HAVE_TIME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <valgrind/memcheck.h> header file. */
/* #undef HAVE_VALGRIND_MEMCHECK_H */

/* Define to 1 if you have the <versionhelpers.h> header file. */
/* #undef HAVE_VERSIONHELPERS_H */

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define to 1 if you have the `writev' function. */
#define HAVE_WRITEV 1

/* Path to ifconfig tool */
#define IFCONFIG_PATH ""

/* Path to iproute tool */
#define IPROUTE_PATH "/usr/sbin/ip"

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* OpenVPN major version - integer */
#define OPENVPN_VERSION_MAJOR 2

/* OpenVPN minor version - integer */
#define OPENVPN_VERSION_MINOR 7

/* OpenVPN patch level - may be a string or integer */
#define OPENVPN_VERSION_PATCH "_git"

/* Version in windows resource format */
#define OPENVPN_VERSION_RESOURCE 2,7,0,0

/* Path to p11tool */
/* #undef P11TOOL_PATH */

/* Name of package */
#define PACKAGE "openvpn"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "openvpn-users@lists.sourceforge.net"

/* Define to the full name of this package. */
#define PACKAGE_NAME "OpenVPN"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "OpenVPN 2.7_git"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "openvpn"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.7_git"

/* Enable pedantic mode */
/* #undef PEDANTIC */

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Path to route tool */
#define ROUTE_PATH ""

/* SIGHUP replacement */
/* #undef SIGHUP */

/* SIGINT replacement */
/* #undef SIGINT */

/* SIGTERM replacement */
/* #undef SIGTERM */

/* SIGUSR1 replacement */
/* #undef SIGUSR1 */

/* SIGUSR2 replacement */
/* #undef SIGUSR2 */

/* The size of `unsigned int', as computed by sizeof. */
#define SIZEOF_UNSIGNED_INT 4

/* The size of `unsigned long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG 8

/* Path to softhsm2 module */
/* #undef SOFTHSM2_MODULE_PATH */

/* Path to softhsm2-util */
/* #undef SOFTHSM2_UTIL_PATH */

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Path to systemd-ask-password tool */
#define SYSTEMD_ASK_PASSWORD_PATH "/usr/bin/systemd-ask-password"

/* systemd is newer than v216 */
/* #undef SYSTEMD_NEWER_THAN_216 */

/* The tap-windows id */
#define TAP_WIN_COMPONENT_ID "tap0901"

/* The tap-windows version number is required for OpenVPN */
#define TAP_WIN_MIN_MAJOR 9

/* The tap-windows version number is required for OpenVPN */
#define TAP_WIN_MIN_MINOR 9

/* Are we running AIX? */
/* #undef TARGET_AIX */

/* A string representing our host */
#define TARGET_ALIAS "x86_64-pc-linux-gnu"

/* Are we running on Mac OS X? */
/* #undef TARGET_DARWIN */

/* Are we running on DragonFlyBSD? */
/* #undef TARGET_DRAGONFLY */

/* Are we running on FreeBSD? */
/* #undef TARGET_FREEBSD */

/* Are we running on Linux? */
#define TARGET_LINUX 1

/* Are we running NetBSD? */
/* #undef TARGET_NETBSD */

/* Are we running on OpenBSD? */
/* #undef TARGET_OPENBSD */

/* Target prefix */
#define TARGET_PREFIX "L"

/* Are we running on Solaris? */
/* #undef TARGET_SOLARIS */

/* Are we running WIN32? */
/* #undef TARGET_WIN32 */

/* dlopen libpam */
/* #undef USE_PAM_DLOPEN */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable general extensions on macOS.  */
#ifndef _DARWIN_C_SOURCE
# define _DARWIN_C_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable X/Open compliant socket functions that do not require linking
   with -lxnet on HP-UX 11.11.  */
#ifndef _HPUX_ALT_XOPEN_SOCKET_API
# define _HPUX_ALT_XOPEN_SOCKET_API 1
#endif
/* Identify the host operating system as Minix.
   This macro does not affect the system headers' behavior.
   A future release of Autoconf may stop defining this macro.  */
#ifndef _MINIX
/* # undef _MINIX */
#endif
/* Enable general extensions on NetBSD.
   Enable NetBSD compatibility extensions on Minix.  */
#ifndef _NETBSD_SOURCE
# define _NETBSD_SOURCE 1
#endif
/* Enable OpenBSD compatibility extensions on NetBSD.
   Oddly enough, this does nothing on OpenBSD.  */
#ifndef _OPENBSD_SOURCE
# define _OPENBSD_SOURCE 1
#endif
/* Define to 1 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_SOURCE
/* # undef _POSIX_SOURCE */
#endif
/* Define to 2 if needed for POSIX-compatible behavior.  */
#ifndef _POSIX_1_SOURCE
/* # undef _POSIX_1_SOURCE */
#endif
/* Enable POSIX-compatible threading on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-5:2014.  */
#ifndef __STDC_WANT_IEC_60559_ATTRIBS_EXT__
# define __STDC_WANT_IEC_60559_ATTRIBS_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-1:2014.  */
#ifndef __STDC_WANT_IEC_60559_BFP_EXT__
# define __STDC_WANT_IEC_60559_BFP_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-2:2015.  */
#ifndef __STDC_WANT_IEC_60559_DFP_EXT__
# define __STDC_WANT_IEC_60559_DFP_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-4:2015.  */
#ifndef __STDC_WANT_IEC_60559_FUNCS_EXT__
# define __STDC_WANT_IEC_60559_FUNCS_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TS 18661-3:2015.  */
#ifndef __STDC_WANT_IEC_60559_TYPES_EXT__
# define __STDC_WANT_IEC_60559_TYPES_EXT__ 1
#endif
/* Enable extensions specified by ISO/IEC TR 24731-2:2010.  */
#ifndef __STDC_WANT_LIB_EXT2__
# define __STDC_WANT_LIB_EXT2__ 1
#endif
/* Enable extensions specified by ISO/IEC 24747:2009.  */
#ifndef __STDC_WANT_MATH_SPEC_FUNCS__
# define __STDC_WANT_MATH_SPEC_FUNCS__ 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable X/Open extensions.  Define to 500 only if necessary
   to make mbstate_t available.  */
#ifndef _XOPEN_SOURCE
/* # undef _XOPEN_SOURCE */
#endif


/* Use valgrind memory debugging library */
/* #undef USE_VALGRIND */

/* Version number of package */
#define VERSION "2.7_git"

/* Use custom user_settings.h file for wolfSSL library */
/* #undef WOLFSSL_USER_SETTINGS */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Workaround missing in_addr_t */
/* #undef in_addr_t */

/* Workaround missing in_port_t */
/* #undef in_port_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define as a signed integer type capable of holding a process identifier. */
/* #undef pid_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* type to use in place of socklen_t if not defined */
/* #undef socklen_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
/* #undef volatile */
