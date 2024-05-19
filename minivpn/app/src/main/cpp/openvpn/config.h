
#ifdef TARGET_LINUX

#define ENABLE_CRYPTO_OPENSSL 1

#define ENABLE_DEBUG 1

#define ENABLE_FRAGMENT 1

/* Enable LZ4 compression library */
#define ENABLE_LZ4 1

/* Enable LZO compression library */
#define ENABLE_LZO 1

/* Enable OFB and CFB cipher modes */
#define ENABLE_OFB_CFB_MODE 1

/* enable sitnl support */
#define ENABLE_SITNL 1

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

/* struct cmsghdr needed for extended socket error support */
#define HAVE_CMSGHDR 1

/* Define to 1 if you have the `daemon' function. */
#define HAVE_DAEMON 1

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

/* Define to 1 if you have the `dup' function. */
#define HAVE_DUP 1

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

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

/* Define to 1 if you have the <lzo/lzo1x.h> header file. */
#define HAVE_LZO_LZO1X_H 1

/* Define to 1 if you have the <lzo/lzoutil.h> header file. */
#define HAVE_LZO_LZOUTIL_H 1

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

/* Define to 1 if you have the `nice' function. */
#define HAVE_NICE 1

/* Define to 1 if you have the `openlog' function. */
#define HAVE_OPENLOG 1

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

/* Define to 1 if you have the `strsep' function. */
#define HAVE_STRSEP 1

/* Define to 1 if you have the `syslog' function. */
#define HAVE_SYSLOG 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/epoll.h> header file. */
#define HAVE_SYS_EPOLL_H 1

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

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

/* Path to ifconfig tool */
#define IFCONFIG_PATH ""

/* Path to iproute tool */
#define IPROUTE_PATH "/usr/sbin/ip"

/* Name of package */
#define PACKAGE "openvpn"

/* Define to the full name of this package. */
#define PACKAGE_NAME "OpenVPN"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "OpenVPN 2.7_git"

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.7_git"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Path to route tool */
#define ROUTE_PATH ""

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* The tap-windows id */
#define TAP_WIN_COMPONENT_ID "tap0901"

/* The tap-windows version number is required for OpenVPN */
#define TAP_WIN_MIN_MAJOR 9

/* The tap-windows version number is required for OpenVPN */
#define TAP_WIN_MIN_MINOR 9


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

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

#endif

#ifdef TARGET_ANDROID

#undef TUNSETPERSIST
#undef CONFIGURE_PF //1
#undef CONFIG_FEATURE_IPROUTE

/* via android.mk */
#define ENABLE_CRYPTO_OPENSSL 1
/* Use LZO compression library */
#define ENABLE_LZO 1
#define ENABLE_SNAPPY 1
#define ENABLE_LZ4 1
#define NEED_COMPAT_LZ4 1

/* Enable debugging support */
#define ENABLE_DEBUG 1

/* Enable internal fragmentation support */
#define ENABLE_FRAGMENT 1

#define ENABLE_MANAGEMENT 1

#define ENABLE_PORT_SHARE 1


// New version
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#define HAVE_LZO_LZOUTIL_H 1
#define HAVE_LZO_LZO1X_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_TIME_H 1
// #define HAVE_CONFIG_VERSION_H 1
#define PATH_SEPARATOR_STR "/"
#define HAVE_SA_FAMILY_T 1

#define HAVE_ARPA_INET_H 1

#define HAVE_CHDIR 1

#define HAVE_CHROOT 1

#define HAVE_CMSGHDR 1

#define HAVE_CPP_VARARG_MACRO_GCC 1

#define HAVE_CPP_VARARG_MACRO_ISO 1

#define HAVE_CTYPE_H 1

#define HAVE_DAEMON 1

#define HAVE_DUP 1

#define HAVE_DUP2 1

#define HAVE_EPOLL_CREATE 1

#define HAVE_ERRNO_H 1

#define HAVE_ERR_H 1

#define HAVE_EXECVE 1

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

/* Define to 1 if you have the `getpwnam' function. */
#define HAVE_GETPWNAM 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* struct in_pktinfo needed for IP_PKTINFO support */
#define HAVE_IN_PKTINFO 1

#define HAVE_IPI_SPEC_DST 1

/* Define to 1 if you have the <linux/errqueue.h> header file. */
#define HAVE_LINUX_ERRQUEUE_H 1

/* Define to 1 if you have the <linux/if_tun.h> header file. */
#define HAVE_LINUX_IF_TUN_H 1

/* Define to 1 if you have the <linux/sockios.h> header file. */
#define HAVE_LINUX_SOCKIOS_H 1

/* Define to 1 if you have the <linux/types.h> header file. */
#define HAVE_LINUX_TYPES_H 1

/* Define to 1 if you have the `listen' function. */
#define HAVE_LISTEN 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the `mlockall' function. */
/* #define HAVE_MLOCKALL 1*/

/* struct msghdr needed for extended socket error support */
#define HAVE_MSGHDR 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/in_systm.h> header file. */
#define HAVE_NETINET_IN_SYSTM_H 1

/* Define to 1 if you have the <netinet/ip.h> header file. */
#define HAVE_NETINET_IP_H 1

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#define HAVE_NETINET_TCP_H 1

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* Define to 1 if you have the `nice' function. */
#define HAVE_NICE 1

/* Define to 1 if you have the `openlog' function. */
#define HAVE_OPENLOG 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `recvmsg' function. */
#define HAVE_RECVMSG 1

/* Define to 1 if you have the <resolv.h> header file. */
#define HAVE_RESOLV_H 1

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

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `stat' function. */
#define HAVE_STAT 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <stropts.h> header file. */
#define HAVE_STROPTS_H 1

/* Define to 1 if you have the `syslog' function. */
 #define HAVE_SYSLOG 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/epoll.h> header file. */
#define HAVE_SYS_EPOLL_H 1

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

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

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the `time' function. */
#define HAVE_TIME 1

/* struct tun_pi needed for IPv6 support */
#define HAVE_TUN_PI 1

/* Define to 1 if you have the `umask' function. */
#define HAVE_UMASK 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Path to ifconfig tool */
#define IFCONFIG_PATH "/system/xbin/ifconfig"

/* Path to iproute tool */
#define IPROUTE_PATH "ip"

/* Name of package */
#define PACKAGE "openvpn"

/* Define to the full name of this package. */
#define PACKAGE_NAME "OpenVPN"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "OpenVPN 2.6-icsopenvpn"

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.6_master"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Path to route tool */
#define ROUTE_PATH "/system/xbin/route"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#ifndef __cplusplus
/* #undef inline */
#endif

#define IPPROTO_IP IPPROTO_IP
#define IPPROTO_TCP IPPROTO_TCP

#define ENABLE_OFB_CFB_MODE 1

#endif
