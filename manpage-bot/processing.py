import re
from pprint import pprint


MANPAGE = """man7.org > Linux > man-pages
Linux/UNIX system programming training
Linux man pages: alphabetic list of all pages

Jump to letter: .  3  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p  q  r  s  t  u  v  w  x  y  z

top
    .ldaprc(5) - LDAP configuration file/environment variables

top
    30-systemd-environment-d-generator(7) - List all manpages from the systemd project
    30-systemd-environment-d-generator(8) - Load variables specified by environment.d

top
    a64l(3) - convert between long and base-64
    a64l(3p) - bit integer and a radix-64 ASCII string
    abicompat(1) - check ABI compatibility
    abidiff(1) - compare ABIs of ELF files
    abidw(1) - serialize the ABI of an ELF file
    abilint(1) - validate an abigail ABI representation
    abipkgdiff(1) - compare ABIs of ELF files in software packages
    abort(3) - cause abnormal process termination
    abort(3p) - generate an abnormal process abort
    abs(3) - compute the absolute value of an integer
    abs(3p) - return an integer absolute value
    ac(1) - print statistics about users' connect time
    accept(2) - accept a connection on a socket
    accept(3p) - accept a new connection on a socket
    accept4(2) - accept a connection on a socket
    access(2) - check user's permissions for a file
    access(3p) - determine accessibility of a file relative to directory file descriptor
    access.conf(5) - the login access control table file
    accessdb(8) - dumps the content of a man-db database in a human readable format
    acct(2) - switch process accounting on or off
    acct(5) - process accounting file
    accton(8) - turns process accounting on or off
    acl(5) - Access Control Lists
    acl_add_perm(3) - add a permission to an ACL permission set
    acl_calc_mask(3) - calculate the file group class mask
    acl_check(3) - check an ACL for validity
    acl_clear_perms(3) - clear all permissions from an ACL permission set
    acl_cmp(3) - compare two ACLs
    acl_copy_entry(3) - copy an ACL entry
    acl_copy_ext(3) - copy an ACL from internal to external representation
    acl_copy_int(3) - copy an ACL from external to internal representation
    acl_create_entry(3) - create a new ACL entry
    acl_delete_def_file(3) - delete a default ACL by filename
    acl_delete_entry(3) - delete an ACL entry
    acl_delete_perm(3) - delete a permission from an ACL permission set
    acl_dup(3) - duplicate an ACL
    acl_entries(3) - return the number of entries in an ACL
    acl_equiv_mode(3) - check for an equivalent ACL
    acl_error(3) - convert an ACL error code to a text message
    acl_extended_fd(3) - test for information in the ACL by file descriptor
    acl_extended_file(3) - test for information in ACLs by file name
    acl_extended_file_nofollow(3) - test for information in ACLs by file name
    acl_free(3) - release memory allocated to an ACL data object
    acl_from_mode(3) - create an ACL from file permission bits
    acl_from_text(3) - create an ACL from text
    acl_get_entry(3) - get an ACL entry
    acl_get_fd(3) - get an ACL by file descriptor
    acl_get_file(3) - get an ACL by filename
    acl_get_perm(3) - test for a permission in an ACL permission set
    acl_get_permset(3) - retrieve the permission set from an ACL entry
    acl_get_qualifier(3) - retrieve the qualifier from an ACL entry
    acl_get_tag_type(3) - get the tag type of an ACL entry
    acl_init(3) - initialize ACL working storage
    acl_set_fd(3) - set an ACL by file descriptor
    acl_set_file(3) - set an ACL by filename
    acl_set_permset(3) - set the permission set in an ACL entry
    acl_set_qualifier(3) - set the qualifier of an ACL entry
    acl_set_tag_type(3) - set the tag type of an ACL entry
    acl_size(3) - get the size of the external representation of an ACL
    acl_to_any_text(3) - convert an ACL to text
    acl_to_text(3) - convert an ACL to text
    acl_valid(3) - validate an ACL
    acos(3) - arc cosine function
    acos(3p) - arc cosine functions
    acosf(3) - arc cosine function
    acosf(3p) - arc cosine functions
    acosh(3) - inverse hyperbolic cosine function
    acosh(3p) - inverse hyperbolic cosine functions
    acoshf(3) - inverse hyperbolic cosine function
    acoshf(3p) - inverse hyperbolic cosine functions
    acoshl(3) - inverse hyperbolic cosine function
    acoshl(3p) - inverse hyperbolic cosine functions
    acosl(3) - arc cosine function
    acosl(3p) - arc cosine functions
    acs_map(3x) - curses terminfo global variables
    actions(8) - independently defined actions in tc
    addch(3x) - add a character (with attributes) to a curses window, then advance the cursor
    addchnstr(3x) - add a string of characters (and attributes) to a curses window
    addchstr(3x) - add a string of characters (and attributes) to a curses window
    addftinfo(1) - add information to troff font files for use with groff
    add_key(2) - add a key to the kernel's key management facility
    addmntent(3) - get filesystem descriptor file entry
    addnstr(3x) - add a string of characters to a curses window and advance cursor
    addnwstr(3x) - add a string of wide characters to a curses window and advance cursor
    addpart(8) - tell the kernel about the existence of a partition
    addr2line(1) - convert addresses into file names and line numbers.
    addseverity(3) - introduce new severity classes
    addstr(3x) - add a string of characters to a curses window and advance cursor
    add_wch(3x) - add a complex character and rendition to a curses window, then advance the cursor
    add_wchnstr(3x) - add an array of complex characters (and attributes) to a curses window
    add_wchstr(3x) - add an array of complex characters (and attributes) to a curses window
    addwstr(3x) - add a string of wide characters to a curses window and advance cursor
    adjtime(3) - correct the time to synchronize the system clock
    adjtime(5) - information about hardware clock setting and drift factor
    adjtime_config(5) - information about hardware clock setting and drift factor
    adjtimex(2) - tune kernel clock
    admin(1p) - create and administer SCCS files (DEVELOPMENT)
    afmtodit(1) - create font files for use with groff -Tps and -Tpdf
    afs_syscall(2) - unimplemented system calls
    __after_morecore_hook(3) - malloc debugging variables
    agetty(8) - alternative Linux getty
    aio(7) - POSIX asynchronous I/O overview
    aio.h(0p) - asynchronous input and output
    aio_cancel(3) - cancel an outstanding asynchronous I/O request
    aio_cancel(3p) - cancel an asynchronous I/O request
    aio_error(3) - get error status of asynchronous I/O operation
    aio_error(3p) - retrieve errors status for an asynchronous I/O operation
    aio_fsync(3) - asynchronous file synchronization
    aio_fsync(3p) - asynchronous file synchronization
    aio_init(3) - asynchronous I/O initialization
    aio_read(3) - asynchronous read
    aio_read(3p) - asynchronous read from a file
    aio_return(3) - get return status of asynchronous I/O operation
    aio_return(3p) - retrieve return status of an asynchronous I/O operation
    aio_suspend(3) - wait for asynchronous I/O operation or timeout
    aio_suspend(3p) - wait for an asynchronous I/O request
    aio_write(3) - asynchronous write
    aio_write(3p) - asynchronous write to a file
    alarm(2) - set an alarm clock for delivery of a signal
    alarm(3p) - schedule an alarm signal
    alias(1p) - define or display aliases
    aligned_alloc(3) - allocate aligned memory
    alloca(3) - allocate memory that is automatically freed
    alloc_hugepages(2) - allocate or free huge pages
    alloc_pair(3x) - new curses color-pair functions
    alphasort(3) - scan a directory for matching entries
    alphasort(3p) - scan a directory
    anacron(8) - runs commands periodically
    anacrontab(5) - configuration file for Anacron
    and(3) - reference the SELinux kernel status without invocation of system calls
    apropos(1) - search the manual page names and descriptions
    ar(1) - create, modify, and extract from archives
    ar(1p) - create and maintain library archives
    arch(1) - print machine hardware name (same as uname -m)
    arch_prctl(2) - set architecture-specific thread state
    argz(3) - functions to handle an argz list
    argz_add(3) - functions to handle an argz list
    argz_add_sep(3) - functions to handle an argz list
    argz_append(3) - functions to handle an argz list
    argz_count(3) - functions to handle an argz list
    argz_create(3) - functions to handle an argz list
    argz_create_sep(3) - functions to handle an argz list
    argz_delete(3) - functions to handle an argz list
    argz_extract(3) - functions to handle an argz list
    argz_insert(3) - functions to handle an argz list
    argz_next(3) - functions to handle an argz list
    argz_replace(3) - functions to handle an argz list
    argz_stringify(3) - functions to handle an argz list
    aria_chk(1) - Aria table-maintenance utility
    aria_dump_log(1) - Dump content of Aria log pages.
    aria_ftdump(1) - display full-text index information
    aria_pack(1) - generate compressed, read-only Aria tables
    aria_read_log(1) - display Aria log file contents
    arm_fadvise(2) - predeclare an access pattern for file data
    arm_fadvise64_64(2) - predeclare an access pattern for file data
    armscii-8(7) - Armenian character set encoded in octal, decimal, and hexadecimal
    arm_sync_file_range(2) - sync a file segment with disk
    arp(7) - Linux ARP kernel module.
    arp(8) - manipulate the system ARP cache
    arpa_inet.h(0p) - definitions for internet operations
    arpd(8) - userspace arp daemon.
    arping(8) - send ARP REQUEST to a neighbour host
    AS(1) - the portable GNU assembler.
    as(1) - the portable GNU assembler.
    asa(1p) - control characters
    ascii(7) - ASCII character set encoded in octal, decimal, and hexadecimal
    asctime(3) - transform date and time to broken-down time or ASCII
    asctime(3p) - convert date and time to a string
    asctime_r(3) - transform date and time to broken-down time or ASCII
    asctime_r(3p) - convert date and time to a string
    asin(3) - arc sine function
    asin(3p) - arc sine function
    asinf(3) - arc sine function
    asinf(3p) - arc sine function
    asinh(3) - inverse hyperbolic sine function
    asinh(3p) - inverse hyperbolic sine functions
    asinhf(3) - inverse hyperbolic sine function
    asinhf(3p) - inverse hyperbolic sine functions
    asinhl(3) - inverse hyperbolic sine function
    asinhl(3p) - inverse hyperbolic sine functions
    asinl(3) - arc sine function
    asinl(3p) - arc sine function
    asprintf(3) - print to allocated string
    assert(3) - abort the program if assertion is false
    assert(3p) - insert program diagnostics
    assert.h(0p) - verify program assertion
    assert_perror(3) - test errnum and abort
    assume_default_colors(3x) - use terminal's default colors
    astraceroute(8) - autonomous system trace route utility
    at(1p) - execute commands at a later time
    atan(3) - arc tangent function
    atan(3p) - arc tangent function
    atan2(3) - arc tangent function of two variables
    atan2(3p) - arc tangent functions
    atan2f(3) - arc tangent function of two variables
    atan2f(3p) - arc tangent functions
    atan2l(3) - arc tangent function of two variables
    atan2l(3p) - arc tangent functions
    atanf(3) - arc tangent function
    atanf(3p) - arc tangent function
    atanh(3) - inverse hyperbolic tangent function
    atanh(3p) - inverse hyperbolic tangent functions
    atanhf(3) - inverse hyperbolic tangent function
    atanhf(3p) - inverse hyperbolic tangent functions
    atanhl(3) - inverse hyperbolic tangent function
    atanhl(3p) - inverse hyperbolic tangent functions
    atanl(3) - arc tangent function
    atanl(3p) - arc tangent function
    atexit(3) - register a function to be called at normal process termination
    atexit(3p) - register a function to run at process termination
    atof(3) - convert a string to a double
    atof(3p) - precision number
    atoi(3) - convert a string to an integer
    atoi(3p) - convert a string to an integer
    atol(3) - convert a string to an integer
    atol(3p) - convert a string to a long integer
    atoll(3) - convert a string to an integer
    atoll(3p) - convert a string to a long integer
    atoprc(5) - pcp-atop/pcp-atopsar related resource file
    atoq(3) - convert a string to an integer
    attr(1) - extended attributes on XFS filesystem objects
    attr(5) - Extended attributes
    attr_get(3) - get the value of a user attribute of a filesystem object
    attr_get(3x) - curses character and window attribute control routines
    attr_getf(3) - get the value of a user attribute of a filesystem object
    attributes(7) - POSIX safety concepts
    attr_list(3) - list the names of the user attributes of a filesystem object
    attr_list_by_handle(3) - file handle operations
    attr_listf(3) - list the names of the user attributes of a filesystem object
    attr_multi(3) - manipulate multiple user attributes on a filesystem object at once
    attr_multi_by_handle(3) - file handle operations
    attr_multif(3) - manipulate multiple user attributes on a filesystem object at once
    attroff(3x) - curses character and window attribute control routines
    attr_off(3x) - curses character and window attribute control routines
    attron(3x) - curses character and window attribute control routines
    attr_on(3x) - curses character and window attribute control routines
    attr_remove(3) - remove a user attribute of a filesystem object
    attr_removef(3) - remove a user attribute of a filesystem object
    attr_set(3) - set the value of a user attribute of a filesystem object
    attrset(3x) - curses character and window attribute control routines
    attr_set(3x) - curses character and window attribute control routines
    attr_setf(3) - set the value of a user attribute of a filesystem object
    audispd-zos-remote(8) - z/OS Remote-services Audit dispatcher plugin
    audit-plugins(5) - realtime event receivers
    audit.rules(7) - a set of rules loaded in the kernel audit system
    audit2allow(1) - generate SELinux policy allow/dontaudit rules from logs of denied operations
    audit2why(1) - generate SELinux policy allow/dontaudit rules from logs of denied operations
    audit_add_rule_data(3) - Add new audit rule
    audit_add_watch(3) - create a rule layout for a watch
    auditctl(8) - a utility to assist controlling the kernel's audit system
    auditd-plugins(5) - realtime event receivers
    auditd(8) - The Linux Audit daemon
    auditd.conf(5) - audit daemon configuration file
    audit_delete_rule_data(3) - Delete audit rule
    audit_detect_machine(3) - Detects the current machine type
    audit_encode_nv_string(3) - encode a name/value pair in a string
    audit_getloginuid(3) - Get a program's loginuid value
    audit_get_reply(3) - Get the audit system's reply
    audit_get_session(3) - Get a program's login session id value
    audit_log_acct_message(3) - log a user account message
    audit_log_semanage_message(3) - log a semanage message
    audit_log_user_avc_message(3) - log a user avc message
    audit_log_user_command(3) - log a user command
    audit_log_user_comm_message(3) - log a user message from a console app
    audit_log_user_message(3) - log a general user message
    audit_open(3) - Open a audit netlink socket connection
    audit_request_rules_list_data(3) - Request list of current audit rules
    audit_request_signal_info(3) - Request signal info for the audit system
    audit_request_status(3) - Request status of the audit system
    audit_set_backlog_limit(3) - Set the audit backlog limit
    audit_set_backlog_wait_time(3) - Set the audit backlog wait time
    audit_set_enabled(3) - Enable or disable auditing
    audit_set_failure(3) - Set audit failure flag
    audit_setloginuid(3) - Set a program's loginuid value
    audit_set_pid(3) - Set audit daemon process ID
    audit_set_rate_limit(3) - Set audit rate limit
    audit_update_watch_perms(3) - update permissions field of watch command
    augenrules(8) - a script that merges component audit rule files
    auparse_add_callback(3) - add a callback handler for notifications
    auparse_destroy(3) - release instance of parser
    auparse_feed(3) - feed data into parser
    auparse_feed_age_events(3) - check events for complete based on time.
    auparse_feed_has_data(3) - check if there is any data accumulating that might need flushing.
    auparse_find_field(3) - search for field name
    auparse_find_field_next(3) - find next occurrence of field name
    auparse_first_field(3) - reposition field cursor
    auparse_first_record(3) - reposition record cursor
    auparse_flush_feed(3) - flush any unconsumed feed data through parser.
    auparse_get_field_int(3) - get current field's value as an int
    auparse_get_field_name(3) - get current field's name
    auparse_get_field_num(3) - get current field cursor location
    auparse_get_field_str(3) - get current field's value
    auparse_get_field_type(3) - get current field's data type
    auparse_get_filename(3) - get the filename where record was found
    auparse_get_line_number(3) - get line number where record was found
    auparse_get_milli(3) - get the millisecond value of the event
    auparse_get_node(3) - get the event's machine node name
    auparse_get_num_fields(3) - get the number of fields
    auparse_get_num_records(3) - get the number of records
    auparse_get_record_num(3) - get current record cursor location
    auparse_get_record_text(3) - access unparsed record data
    auparse_get_serial(3) - get the event's serial number
    auparse_get_time(3) - get event's time
    auparse_get_timestamp(3) - access timestamp of the event
    auparse_get_type(3) - get record's type
    auparse_get_type_name(3) - get record's type translation
    auparse_goto_field_num(3) - move field cursor to specific field
    auparse_goto_record_num(3) - move record cursor to specific record
    auparse_init(3) - initialize an instance of the audit parsing library
    auparse_interpret_field(3) - get current field's interpreted value
    auparse_interpret_realpath(3) - get current field's interpreted value
    auparse_interpret_sock_address(3) - get current field's interpreted value
    auparse_interpret_sock_family(3) - get current field's interpreted value
    auparse_interpret_sock_port(3) - get current field's interpreted value
    auparse_next_event(3) - get the next event
    auparse_next_field(3) - move field cursor
    auparse_next_record(3) - move record cursor
    auparse_node_compare(3) - compares node name values
    auparse_normalize(3) - normalize the current event
    auparse_normalize_functions(3) - Access normalized fields
    auparse_normalize_get_action(3) - Access normalized fields
    auparse_normalize_get_event_kind(3) - Access normalized fields
    auparse_normalize_get_results(3) - Access normalized fields
    auparse_normalize_how(3) - Access normalized fields
    auparse_normalize_key(3) - Access normalized fields
    auparse_normalize_object_first_attribute(3) - Access normalized fields
    auparse_normalize_object_kind(3) - Access normalized fields
    auparse_normalize_object_next_attribute(3) - Access normalized fields
    auparse_normalize_object_primary(3) - Access normalized fields
    auparse_normalize_object_primary2(3) - Access normalized fields
    auparse_normalize_object_secondary(3) - Access normalized fields
    auparse_normalize_session(3) - Access normalized fields
    auparse_normalize_subject_first_attribute(3) - Access normalized fields
    auparse_normalize_subject_kind(3) - Access normalized fields
    auparse_normalize_subject_next_attribute(3) - Access normalized fields
    auparse_normalize_subject_primary(3) - Access normalized fields
    auparse_normalize_subject_secondary(3) - Access normalized fields
    auparse_reset(3) - reset audit parser instance
    auparse_set_escape_mode(3) - choose escape method
    auparse_timestamp_compare(3) - compares timestamp values
    aureport(8) - a tool that produces summary reports of audit daemon logs
    ausearch-expression(5) - audit search expression format
    ausearch(8) - a tool to query audit daemon logs
    ausearch_add_expression(3) - build up search expression
    ausearch_add_interpreted_item(3) - build up search rule
    ausearch_add_item(3) - build up search rule
    ausearch_add_regex(3) - use regular expression search rule
    ausearch_add_timestamp_item(3) - build up search rule
    ausearch_add_timestamp_item_ex(3) - build up search rule
    ausearch_clear(3) - clear search parameters
    ausearch_next_event(3) - find the next event that meets search criteria
    ausearch_set_stop(3) - set the cursor position
    auth_destroy(3) - library routines for remote procedure calls
    authnone_create(3) - library routines for remote procedure calls
    authunix_create(3) - library routines for remote procedure calls
    authunix_create_default(3) - library routines for remote procedure calls
    auto.master(5) - Master Map for automounter consulted by autofs
    autofs(5) - Format of the automounter maps
    autofs(8) - Service control for the automounter
    autofs.conf(5) - autofs configuration
    autofsd-probe(1) - probe AutoFS mount/unmount daemon
    autofs_ldap_auth.conf(5) - autofs LDAP authentication configuration
    automount(8) - manage autofs mount points
    autopoint(1) - copies standard gettext infrastructure
    autrace(8) - a program similar to strace
    avc_add_callback(3) - additional event notification for SELinux userspace object managers
    avc_audit(3) - obtain and audit SELinux access decisions
    avc_av_stats(3) - obtain userspace SELinux AVC statistics
    avc_cache_stats(3) - obtain userspace SELinux AVC statistics
    avc_cleanup(3) - userspace SELinux AVC setup and teardown
    avc_compute_create(3) - obtain SELinux label for new object
    avc_compute_member(3) - obtain SELinux label for new object
    avc_context_to_sid(3) - obtain and manipulate SELinux security ID's
    avc_destroy(3) - userspace SELinux AVC setup and teardown
    avc_entry_ref_init(3) - obtain and audit SELinux access decisions
    avc_get_initial_context(3) - obtain and manipulate SELinux security ID's
    avc_get_initial_sid(3) - obtain and manipulate SELinux security ID's
    avc_has_perm(3) - obtain and audit SELinux access decisions
    avc_has_perm_noaudit(3) - obtain and audit SELinux access decisions
    avc_init(3) - legacy userspace SELinux AVC setup
    avc_netlink_acquire_fd(3) - SELinux netlink processing
    avc_netlink_check_nb(3) - SELinux netlink processing
    avc_netlink_close(3) - SELinux netlink processing
    avc_netlink_loop(3) - SELinux netlink processing
    avc_netlink_open(3) - SELinux netlink processing
    avc_netlink_release_fd(3) - SELinux netlink processing
    avc_open(3) - userspace SELinux AVC setup and teardown
    avc_reset(3) - userspace SELinux AVC setup and teardown
    avc_sid_stats(3) - obtain userspace SELinux AVC statistics
    avc_sid_to_context(3) - obtain and manipulate SELinux security ID's
    avcstat(8) - Display SELinux AVC statistics
    awk(1p) - pattern scanning and processing language

top
    b2sum(1) - compute and check BLAKE2 message digest
    babeltrace-convert(1) - Convert one or more traces
    babeltrace-filter.lttng-utils.debug-info(7) - Babeltrace's debugging information filter component class for LTTng traces
    babeltrace-filter.utils.muxer(7) - Babeltrace's notification multiplexer filter component class
    babeltrace-filter.utils.trimmer(7) - Babeltrace's trimmer filter component class
    babeltrace-help(1) - Get help for a Babeltrace plugin or component class
    babeltrace-intro(7) - Introduction to Babeltrace
    babeltrace-list-plugins(1) - List Babeltrace plugins and their properties
    babeltrace-log(1) - Convert a Linux kernel ring buffer to a CTF trace
    babeltrace-plugin-ctf(7) - Babeltrace's CTF plugin
    babeltrace-plugin-lttng-utils(7) - Babeltrace's LTTng utilities plugin
    babeltrace-plugin-text(7) - Babeltrace's plain text plugin
    babeltrace-plugin-utils(7) - Babeltrace's utilities plugin
    babeltrace-query(1) - Query object from a component class
    babeltrace-run(1) - Create a trace processing graph and run it
    babeltrace-sink.ctf.fs(7) - Babeltrace's file system CTF sink component class
    babeltrace-sink.text.pretty(7) - Babeltrace's pretty-printing sink component class
    babeltrace-sink.utils.counter(7) - Babeltrace's notification counter sink component class
    babeltrace-sink.utils.dummy(7) - Babeltrace's dummy sink component class
    babeltrace-source.ctf.fs(7) - Babeltrace's file system CTF source component class
    babeltrace-source.ctf.lttng-live(7) - Babeltrace's LTTng live source component class
    babeltrace-source.text.dmesg(7) - Babeltrace's Linux kernel ring buffer source component class
    babeltrace(1) - Convert or process one or more traces, and more
    backend(7) - cups backend transmission interfaces
    backtrace(3) - support for application self-debugging
    backtrace_symbols(3) - support for application self-debugging
    backtrace_symbols_fd(3) - support for application self-debugging
    badblocks(8) - search a device for bad blocks
    base32(1) - base32 encode/decode data and print to standard output
    base64(1) - base64 encode/decode data and print to standard output
    basename(1) - strip directory and suffix from filenames
    basename(1p) - directory portion of a pathname
    basename(3) - parse pathname components
    basename(3p) - return the last component of a pathname
    bash(1) - GNU Bourne-Again SHell
    basic(8) - basic traffic control filter
    batch(1p) - schedule commands to be executed in a batch queue
    baudrate(3x) - curses environment query routines
    bc(1p) - precision arithmetic language
    BC(3x) - direct curses interface to the terminfo capability database
    bcmp(3) - compare byte sequences
    bcopy(3) - copy byte sequence
    bdflush(2) - start, flush, or tune buffer-dirty-flush daemon
    be16toh(3) - convert values between host and big-/little-endian byte order
    be32toh(3) - convert values between host and big-/little-endian byte order
    be64toh(3) - convert values between host and big-/little-endian byte order
    beep(3x) - curses bell and screen flash routines
    ber_alloc_t(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_bvarray_add(3) - OpenLDAP LBER types and allocation functions
    ber_bvarray_free(3) - OpenLDAP LBER types and allocation functions
    ber_bvdup(3) - OpenLDAP LBER types and allocation functions
    ber_bvecadd(3) - OpenLDAP LBER types and allocation functions
    ber_bvecfree(3) - OpenLDAP LBER types and allocation functions
    ber_bvfree(3) - OpenLDAP LBER types and allocation functions
    ber_bvstr(3) - OpenLDAP LBER types and allocation functions
    ber_bvstrdup(3) - OpenLDAP LBER types and allocation functions
    ber_dupbv(3) - OpenLDAP LBER types and allocation functions
    BerElement(3) - OpenLDAP LBER types and allocation functions
    ber_first_element(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_flush(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_flush2(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_free(3) - OpenLDAP LBER types and allocation functions
    ber_get_bitstring(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_boolean(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_enum(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_int(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_next(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_null(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_stringa(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_stringal(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_stringb(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_get_stringbv(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_init(3) - OpenLDAP LBER types and allocation functions
    ber_init2(3) - OpenLDAP LBER types and allocation functions
    ber_int_t(3) - OpenLDAP LBER types and allocation functions
    ber_len_t(3) - OpenLDAP LBER types and allocation functions
    ber_memalloc(3) - OpenLDAP LBER memory allocators
    ber_memcalloc(3) - OpenLDAP LBER memory allocators
    ber_memfree(3) - OpenLDAP LBER memory allocators
    ber_memrealloc(3) - OpenLDAP LBER memory allocators
    ber_memvfree(3) - OpenLDAP LBER memory allocators
    ber_next_element(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_peek_tag(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_printf(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_bitstring(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_boolean(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_enum(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_int(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_null(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_ostring(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_seq(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_set(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_put_string(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_scanf(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_skip_tag(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    ber_slen_t(3) - OpenLDAP LBER types and allocation functions
    ber_sockbuf_add_io(3) - OpenLDAP LBER I/O infrastructure
    ber_sockbuf_alloc(3) - OpenLDAP LBER I/O infrastructure
    ber_sockbuf_ctrl(3) - OpenLDAP LBER I/O infrastructure
    ber_sockbuf_free(3) - OpenLDAP LBER I/O infrastructure
    ber_sockbuf_remove_io(3) - OpenLDAP LBER I/O infrastructure
    ber_start_seq(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_start_set(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    ber_str2bv(3) - OpenLDAP LBER types and allocation functions
    ber_tag_t(3) - OpenLDAP LBER types and allocation functions
    ber_uint_t(3) - OpenLDAP LBER types and allocation functions
    berval(3) - OpenLDAP LBER types and allocation functions
    BerValue(3) - OpenLDAP LBER types and allocation functions
    BerVarray(3) - OpenLDAP LBER types and allocation functions
    bfifo(8) - Packet limited First In, First Out queue
    bg(1p) - run jobs in the background
    bind(2) - bind a name to a socket
    bind(3p) - bind a name to a socket
    bindresvport(3) - bind a socket to a privileged IP port
    bindtextdomain(3) - set directory containing message catalogs
    bind_textdomain_codeset(3) - set encoding of message translations
    binfmt.d(5) - Configure additional binary formats for executables at boot
    bkgd(3x) - curses window background manipulation routines
    bkgdset(3x) - curses window background manipulation routines
    bkgrnd(3x) - curses window complex background manipulation routines
    bkgrndset(3x) - curses window complex background manipulation routines
    blkdeactivate(8) - utility to deactivate block devices
    blkdiscard(8) - discard sectors on a device
    blkid(8) - locate/print block device attributes
    blkiomon(8) - monitor block device I/O based o blktrace data
    blkmapd(8) - pNFS block layout mapping daemon
    blkparse(1) - produce formatted output of event streams of block devices
    blkrawverify(1) - verifies an output file produced by blkparse
    blktrace(8) - generate traces of the i/o traffic on block devices
    blkzone(8) - run zone command on a device
    blockdev(8) - call block device ioctls from the command line
    bno_plot(1) - generate interactive 3D plot of IO blocks and sizes
    boolcodes(3x) - curses terminfo global variables
    booleans(5) - The SELinux booleans configuration files
    booleans(8) - Policy booleans enable runtime customization of SELinux policy
    boolfnames(3x) - curses terminfo global variables
    boolnames(3x) - curses terminfo global variables
    boot(7) - System bootup process based on UNIX System V Release 4
    bootchart.conf(5) - Boot performance analysis graphing tool configuration files
    bootchart.conf.d(5) - Boot performance analysis graphing tool configuration files
    bootctl(1) - Control the firmware and boot manager settings
    bootparam(7) - introduction to boot time parameters of the Linux kernel
    bootup(7) - System bootup process
    border(3x) - create curses borders, horizontal and vertical lines
    border_set(3x) - create curses borders or lines using complex characters and renditions
    box(3x) - create curses borders, horizontal and vertical lines
    box_set(3x) - create curses borders or lines using complex characters and renditions
    bpf(2) - perform a command on an extended BPF map or program
    BPF(8) - BPF programmable classifier and actions for ingress/egress queueing disciplines
    bpfc(8) - a Berkeley Packet Filter assembler and compiler
    brctl(8) - ethernet bridge administration
    break(1p) - exit from for, while, or until loop
    break(2) - unimplemented system calls
    bridge(8) - show / manipulate bridge addresses and devices
    brk(2) - change data segment size
    bsd_signal(3) - signal handling with BSD semantics
    bsearch(3) - binary search of a sorted array
    bsearch(3p) - binary search a sorted table
    bstring(3) - byte string operations
    bswap(3) - reverse order of bytes
    bswap_16(3) - reverse order of bytes
    bswap_32(3) - reverse order of bytes
    bswap_64(3) - reverse order of bytes
    btowc(3) - convert single byte to wide character
    btowc(3p) - single byte to wide character conversion
    btrace(8) - perform live tracing for block devices
    btrecord(8) - recreate IO loads recorded by blktrace
    btree(3) - btree database access method
    btreplay(8) - recreate IO loads recorded by blktrace
    btrfs-balance(8) - balance block groups on a btrfs filesystem
    btrfs-check(8) - check or repair a btrfs filesystem
    btrfs-convert(8) - convert from ext2/3/4 or reiserfs filesystem to btrfs in-place
    btrfs-device(8) - manage devices of btrfs filesystems
    btrfs-filesystem(8) - command group that primarily does work on the whole filesystems
    btrfs-find-root(8) - filter to find btrfs root
    btrfs-image(8) - create/restore an image of the filesystem
    btrfs-inspect-internal(8) - query various internal information
    btrfs-map-logical(8) - map btrfs logical extent to physical extent
    btrfs-property(8) - get/set/list properties for given filesystem object
    btrfs-qgroup(8) - control the quota group of a btrfs filesystem
    btrfs-quota(8) - control the global quota status of a btrfs filesystem
    btrfs-receive(8) - receive subvolumes from send stream
    btrfs-replace(8) - replace devices managed by btrfs with other device.
    btrfs-rescue(8) - Recover a damaged btrfs filesystem
    btrfs-restore(8) - try to restore files from a damaged btrfs filesystem image
    btrfs-scrub(8) - scrub btrfs filesystem, verify block checksums
    btrfs-select-super(8) - overwrite primary superblock with a backup copy
    btrfs-send(8) - generate a stream of changes between two subvolume snapshots
    btrfs-subvolume(8) - manage btrfs subvolumes
    btrfs(8) - a toolbox to manage btrfs filesystems
    btrfstune(8) - tune various filesystem parameters
    btt(1) - analyse block i/o traces produces by blktrace
    bufferevent_base_set(3) - execute a function when a specific event occurs
    bufferevent_disable(3) - execute a function when a specific event occurs
    bufferevent_enable(3) - execute a function when a specific event occurs
    bufferevent_free(3) - execute a function when a specific event occurs
    bufferevent_new(3) - execute a function when a specific event occurs
    bufferevent_read(3) - execute a function when a specific event occurs
    bufferevent_settimeout(3) - execute a function when a specific event occurs
    bufferevent_write(3) - execute a function when a specific event occurs
    bufferevent_write_buffer(3) - execute a function when a specific event occurs
    busctl(1) - Introspect the bus
    byteorder(3) - convert values between host and network byte order
    bzero(3) - zero a byte string

top
    c99(1p) - compile standard C programs
    cabs(3) - absolute value of a complex number
    cabs(3p) - return a complex absolute value
    cabsf(3) - absolute value of a complex number
    cabsf(3p) - return a complex absolute value
    cabsl(3) - absolute value of a complex number
    cabsl(3p) - return a complex absolute value
    cacheflush(2) - flush contents of instruction and/or data cache
    cacos(3) - complex arc cosine
    cacos(3p) - complex arc cosine functions
    cacosf(3) - complex arc cosine
    cacosf(3p) - complex arc cosine functions
    cacosh(3) - complex arc hyperbolic cosine
    cacosh(3p) - complex arc hyperbolic cosine functions
    cacoshf(3) - complex arc hyperbolic cosine
    cacoshf(3p) - complex arc hyperbolic cosine functions
    cacoshl(3) - complex arc hyperbolic cosine
    cacoshl(3p) - complex arc hyperbolic cosine functions
    cacosl(3) - complex arc cosine
    cacosl(3p) - complex arc cosine functions
    CAKE(8) - Common Applications Kept Enhanced (CAKE)
    cal(1) - display a calendar
    cal(1p) - print a calendar
    callgrind_annotate(1) - post-processing tool for the Callgrind
    callgrind_control(1) - observe and control programs being run by Callgrind
    calloc(3) - allocate and free dynamic memory
    calloc(3p) - a memory allocator
    callrpc(3) - library routines for remote procedure calls
    cancel(1) - cancel jobs
    can_change_color(3x) - curses color manipulation routines
    canonicalize_file_name(3) - return the canonicalized absolute pathname
    capabilities(7) - overview of Linux capabilities
    cap_clear(3) - capability data object manipulation
    cap_clear_flag(3) - capability data object manipulation
    cap_compare(3) - capability data object manipulation
    cap_copy_ext(3) - capability state external representation translation
    cap_copy_int(3) - capability state external representation translation
    cap_drop_bound(3) - capability manipulation on processes
    cap_dup(3) - capability data object storage management
    cap_free(3) - capability data object storage management
    cap_from_name(3) - capability state textual representation translation
    cap_from_text(3) - capability state textual representation translation
    capget(2) - set/get capabilities of thread(s)
    cap_get_bound(3) - capability manipulation on processes
    cap_get_fd(3) - capability manipulation on files
    cap_get_file(3) - capability manipulation on files
    cap_get_flag(3) - capability data object manipulation
    capgetp(3) - capability manipulation on processes
    cap_get_pid(3) - capability manipulation on processes
    cap_get_proc(3) - capability manipulation on processes
    cap_init(3) - capability data object storage management
    capng_apply(3) - apply the stored capabilities settings
    capng_capability_to_name(3) - convert capability integer to text
    capng_change_id(3) - change the credentials retaining capabilities
    capng_clear(3) - clear chosen capabilities set
    capng_fill(3) - fill chosen capabilities set
    capng_get_caps_fd(3) -
    capng_get_caps_process(3) - get the capabilities from a process
    capng_have_capabilities(3) - general check for capabilities
    capng_have_capability(3) - check for specific capability
    capng_lock(3) - lock the current process capabilities settings
    capng_name_to_capability(3) - convert capability text to integer
    capng_print_caps_numeric(3) - print numeric values for capabilities set
    capng_print_caps_text(3) - print names of values for capabilities set
    capng_restore_state(3) - set the internal library state
    capng_save_state(3) - get the internal library state
    capng_set_caps_fd(3) -
    capng_setpid(3) - set working pid
    capng_update(3) - update the stored capabilities settings
    capng_updatev(3) - update the stored capabilities settings
    capset(2) - set/get capabilities of thread(s)
    cap_set_fd(3) - capability manipulation on files
    cap_set_file(3) - capability manipulation on files
    cap_set_flag(3) - capability data object manipulation
    capsetp(3) - capability manipulation on processes
    cap_set_proc(3) - capability manipulation on processes
    capsh(1) - capability shell wrapper
    cap_size(3) - capability state external representation translation
    captest(8) - a program to demonstrate capabilities
    cap_to_name(3) - capability state textual representation translation
    cap_to_text(3) - capability state textual representation translation
    carg(3) - calculate the complex argument
    carg(3p) - complex argument functions
    cargf(3) - calculate the complex argument
    cargf(3p) - complex argument functions
    cargl(3) - calculate the complex argument
    cargl(3p) - complex argument functions
    casin(3) - complex arc sine
    casin(3p) - complex arc sine functions
    casinf(3) - complex arc sine
    casinf(3p) - complex arc sine functions
    casinh(3) - complex arc sine hyperbolic
    casinh(3p) - complex arc hyperbolic sine functions
    casinhf(3) - complex arc sine hyperbolic
    casinhf(3p) - complex arc hyperbolic sine functions
    casinhl(3) - complex arc sine hyperbolic
    casinhl(3p) - complex arc hyperbolic sine functions
    casinl(3) - complex arc sine
    casinl(3p) - complex arc sine functions
    cat(1) - concatenate files and print on the standard output
    cat(1p) - concatenate and print files
    catan(3) - complex arc tangents
    catan(3p) - complex arc tangent functions
    catanf(3) - complex arc tangents
    catanf(3p) - complex arc tangent functions
    catanh(3) - complex arc tangents hyperbolic
    catanh(3p) - complex arc hyperbolic tangent functions
    catanhf(3) - complex arc tangents hyperbolic
    catanhf(3p) - complex arc hyperbolic tangent functions
    catanhl(3) - complex arc tangents hyperbolic
    catanhl(3p) - complex arc hyperbolic tangent functions
    catanl(3) - complex arc tangents
    catanl(3p) - complex arc tangent functions
    catclose(3) - open/close a message catalog
    catclose(3p) - close a message catalog descriptor
    catgets(3) - get message from a message catalog
    catgets(3p) - read a program message
    catman(8) - create or update the pre-formatted manual pages
    catopen(3) - open/close a message catalog
    catopen(3p) - open a message catalog
    cbc_crypt(3) - fast DES encryption
    CBQ(8) - Class Based Queueing
    cbreak(3x) - curses input options
    cbrt(3) - cube root function
    cbrt(3p) - cube root functions
    cbrtf(3) - cube root function
    cbrtf(3p) - cube root functions
    cbrtl(3) - cube root function
    cbrtl(3p) - cube root functions
    CBS(8) - Credit Based Shaper (CBS) Qdisc
    cciss(4) - HP Smart Array block driver
    ccos(3) - complex cosine function
    ccos(3p) - complex cosine functions
    ccosf(3) - complex cosine function
    ccosf(3p) - complex cosine functions
    ccosh(3) - complex hyperbolic cosine
    ccosh(3p) - complex hyperbolic cosine functions
    ccoshf(3) - complex hyperbolic cosine
    ccoshf(3p) - complex hyperbolic cosine functions
    ccoshl(3) - complex hyperbolic cosine
    ccoshl(3p) - complex hyperbolic cosine functions
    ccosl(3) - complex cosine function
    ccosl(3p) - complex cosine functions
    cd(1p) - change the working directory
    ceil(3) - ceiling function: smallest integral value not less than argument
    ceil(3p) - ceiling value function
    ceilf(3) - ceiling function: smallest integral value not less than argument
    ceilf(3p) - ceiling value function
    ceill(3) - ceiling function: smallest integral value not less than argument
    ceill(3p) - ceiling value function
    certtool(1) - GnuTLS certificate tool
    cexp(3) - complex exponential function
    cexp(3p) - complex exponential functions
    cexp2(3) - base-2 exponent of a complex number
    cexp2f(3) - base-2 exponent of a complex number
    cexp2l(3) - base-2 exponent of a complex number
    cexpf(3) - complex exponential function
    cexpf(3p) - complex exponential functions
    cexpl(3) - complex exponential function
    cexpl(3p) - complex exponential functions
    cfdisk(8) - display or manipulate a disk partition table
    cfgetispeed(3) - get and set terminal attributes, line control, get and set baud rate
    cfgetispeed(3p) - get input baud rate
    cfgetospeed(3) - get and set terminal attributes, line control, get and set baud rate
    cfgetospeed(3p) - get output baud rate
    cflow(1p) - language flowgraph (DEVELOPMENT)
    cfmakeraw(3) - get and set terminal attributes, line control, get and set baud rate
    cfree(3) - free allocated memory
    cfsetispeed(3) - get and set terminal attributes, line control, get and set baud rate
    cfsetispeed(3p) - set input baud rate
    cfsetospeed(3) - get and set terminal attributes, line control, get and set baud rate
    cfsetospeed(3p) - set output baud rate
    cfsetspeed(3) - get and set terminal attributes, line control, get and set baud rate
    cg_annotate(1) - post-processing tool for Cachegrind
    cgcc(1) - Compiler wrapper to run Sparse after compiling
    cg_diff(1) - compares two Cachegrind output files
    cg_merge(1) - merges multiple Cachegrind output files into one
    cgroup(8) - control group based traffic control filter
    cgroup_namespaces(7) - overview of Linux cgroup namespaces
    cgroups(7) - Linux control groups
    chacl(1) - change the access control list of a file or directory
    chage(1) - change user password expiry information
    charmap(5) - character set description file
    charsets(7) - character set standards and internationalization
    chattr(1) - change file attributes on a Linux file system
    chcat(8) - change file SELinux security category
    chcon(1) - change file security context
    chcpu(8) - configure CPUs
    chdir(2) - change working directory
    chdir(3p) - change working directory
    checkmodule(8) - SELinux policy module compiler
    checkPasswdAccess(3) - query the SELinux policy database in the kernel
    checkpasswdaccess(3) - query the SELinux policy database in the kernel
    checkpolicy(8) - SELinux policy compiler
    chem(1) - groff preprocessor for producing chemical structure diagrams
    chfn(1) - change your finger information
    chgat(3x) - curses character and window attribute control routines
    chgpasswd(8) - update group passwords in batch mode
    chgrp(1) - change group ownership
    chgrp(1p) - change the file group ownership
    chkcon(8) - determine if a security context is valid for a given binary policy
    chkhelp(1) - check performance metrics help text files
    chmem(8) - configure memory
    chmod(1) - change file mode bits
    chmod(1p) - change the file modes
    chmod(2) - change permissions of a file
    chmod(3p) - change mode of a file relative to directory file descriptor
    choke(8) - choose and keep scheduler
    choom(1) - display and adjust OOM-killer score.
    chown(1) - change file owner and group
    chown(1p) - change the file ownership
    chown(2) - change ownership of a file
    chown(3p) - change owner and group of a file relative to directory file descriptor
    chown32(2) - change ownership of a file
    chpasswd(8) - update passwords in batch mode
    chroot(1) - run command or interactive shell with special root directory
    chroot(2) - change root directory
    chrt(1) - manipulate the real-time attributes of a process
    chsh(1) - change your login shell
    chvt(1) - change foreground virtual terminal
    cifsiostat(1) - Report CIFS statistics.
    cimag(3) - get imaginary part of a complex number
    cimag(3p) - complex imaginary functions
    cimagf(3) - get imaginary part of a complex number
    cimagf(3p) - complex imaginary functions
    cimagl(3) - get imaginary part of a complex number
    cimagl(3p) - complex imaginary functions
    CIRCLEQ_ENTRY(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_entry(3) - linked lists, singly-linked tail queues, lists and tail queues
    CIRCLEQ_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    CIRCLEQ_INIT(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_init(3) - linked lists, singly-linked tail queues, lists and tail queues
    CIRCLEQ_INSERT_AFTER(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_insert_after(3) - linked lists, singly-linked tail queues, lists and tail queues
    CIRCLEQ_INSERT_BEFORE(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_insert_before(3) - linked lists, singly-linked tail queues, lists and tail queues
    CIRCLEQ_INSERT_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_insert_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    CIRCLEQ_INSERT_TAIL(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_insert_tail(3) - linked lists, singly-linked tail queues, lists and tail queues
    CIRCLEQ_REMOVE(3) - linked lists, singly-linked tail queues, lists and tail queues
    circleq_remove(3) - linked lists, singly-linked tail queues, lists and tail queues
    cksum(1) - checksum and count the bytes in a file
    cksum(1p) - write file checksums and sizes
    classes.conf(5) - class configuration file for cups
    CLEAR(1) - clear the terminal screen
    clear(1) - clear the terminal screen
    clear(3x) - clear all or part of a curses window
    clearenv(3) - clear the environment
    clearerr(3) - check and reset stream status
    clearerr(3p) - clear indicators on a stream
    clearerr_unlocked(3) - nonlocking stdio functions
    clearok(3x) - curses output options
    client.conf(5) - client configuration file for cups
    clnt_broadcast(3) - library routines for remote procedure calls
    clnt_call(3) - library routines for remote procedure calls
    clnt_control(3) - library routines for remote procedure calls
    clnt_create(3) - library routines for remote procedure calls
    clnt_destroy(3) - library routines for remote procedure calls
    clnt_freeres(3) - library routines for remote procedure calls
    clnt_geterr(3) - library routines for remote procedure calls
    clnt_pcreateerror(3) - library routines for remote procedure calls
    clnt_perrno(3) - library routines for remote procedure calls
    clnt_perror(3) - library routines for remote procedure calls
    clntraw_create(3) - library routines for remote procedure calls
    clnt_spcreateerror(3) - library routines for remote procedure calls
    clnt_sperrno(3) - library routines for remote procedure calls
    clnt_sperror(3) - library routines for remote procedure calls
    clnttcp_create(3) - library routines for remote procedure calls
    clntudp_bufcreate(3) - library routines for remote procedure calls
    clntudp_create(3) - library routines for remote procedure calls
    clock(3) - determine processor time
    clock(3p) - report CPU time used
    clockdiff(8) - measure clock difference between hosts
    clock_getcpuclockid(3) - obtain ID of a process CPU-time clock
    clock_getcpuclockid(3p) - time clock (ADVANCED REALTIME)
    clock_getres(2) - clock and time functions
    clock_getres(3) - clock and time functions
    clock_getres(3p) - clock and timer functions
    clock_gettime(2) - clock and time functions
    clock_gettime(3) - clock and time functions
    clock_gettime(3p) - clock and timer functions
    clock_nanosleep(2) - high-resolution sleep with specifiable clock
    clock_nanosleep(3p) - high resolution sleep with specifiable clock
    clock_settime(2) - clock and time functions
    clock_settime(3) - clock and time functions
    clock_settime(3p) - clock and timer functions
    clog(3) - natural logarithm of a complex number
    clog(3p) - complex natural logarithm functions
    clog10(3) - base-10 logarithm of a complex number
    clog10f(3) - base-10 logarithm of a complex number
    clog10l(3) - base-10 logarithm of a complex number
    clog2(3) - base-2 logarithm of a complex number
    clog2f(3) - base-2 logarithm of a complex number
    clog2l(3) - base-2 logarithm of a complex number
    clogf(3) - natural logarithm of a complex number
    clogf(3p) - complex natural logarithm functions
    clogl(3) - natural logarithm of a complex number
    clogl(3p) - complex natural logarithm functions
    clone(2) - create a child process
    clone2(2) - create a child process
    __clone2(2) - create a child process
    close(2) - close a file descriptor
    close(3p) - close a file descriptor
    closedir(3) - close a directory
    closedir(3p) - close a directory stream
    closelog(3) - send messages to the system logger
    closelog(3p) - control system log
    clrtobot(3x) - clear all or part of a curses window
    clrtoeol(3x) - clear all or part of a curses window
    cmirrord(8) - cluster mirror log daemon
    cmp(1) - compare two files byte by byte
    cmp(1p) - compare two files
    cmsg(3) - access ancillary data
    CMSG_ALIGN(3) - access ancillary data
    cmsg_align(3) - access ancillary data
    CMSG_DATA(3) - access ancillary data
    cmsg_data(3) - access ancillary data
    CMSG_FIRSTHDR(3) - access ancillary data
    cmsg_firsthdr(3) - access ancillary data
    CMSG_LEN(3) - access ancillary data
    cmsg_len(3) - access ancillary data
    CMSG_NXTHDR(3) - access ancillary data
    cmsg_nxthdr(3) - access ancillary data
    CMSG_SPACE(3) - access ancillary data
    cmsg_space(3) - access ancillary data
    cmtime(1) - RDMA CM connection steps timing test.
    CoDel(8) - Controlled-Delay Active Queue Management algorithm
    col(1) - filter reverse line feeds from input
    colcrt(1) - filter nroff output for CRT previewing
    collectl2pcp(1) - import collectl data to a PCP archive
    colon(1p) - null utility
    color_content(3x) - curses color manipulation routines
    COLOR_PAIR(3x) - curses color manipulation routines
    COLOR_PAIRS(3x) - curses global variables
    COLORS(3x) - curses global variables
    color_set(3x) - curses character and window attribute control routines
    colrm(1) - remove columns from a file
    COLS(3x) - curses global variables
    column(1) - columnate lists
    comm(1) - compare two sorted files line by line
    comm(1p) - select or reject lines common to two files
    command(1p) - execute a simple command
    comp_err(1) - compile MariaDB error message file
    complex(7) - basics of complex mathematics
    complex.h(0p) - complex arithmetic
    compress(1p) - compress data
    config(5) - The SELinux sub-system configuration file.
    confstr(3) - get configuration dependent string variables
    confstr(3p) - get configurable variables
    conj(3) - calculate the complex conjugate
    conj(3p) - complex conjugate functions
    conjf(3) - calculate the complex conjugate
    conjf(3p) - complex conjugate functions
    conjl(3) - calculate the complex conjugate
    conjl(3p) - complex conjugate functions
    connect(2) - initiate a connection on a socket
    connect(3p) - connect a socket
    connmark(8) - netfilter connmark retriever action
    console_codes(4) - Linux console escape and control sequences
    console_ioctl(4) - ioctls for console terminal and virtual consoles
    context_free(3) - Routines to manipulate SELinux security contexts
    context_new(3) - Routines to manipulate SELinux security contexts
    context_range_get(3) - Routines to manipulate SELinux security contexts
    context_range_set(3) - Routines to manipulate SELinux security contexts
    context_role_get(3) - Routines to manipulate SELinux security contexts
    context_role_set(3) - Routines to manipulate SELinux security contexts
    context_str(3) - Routines to manipulate SELinux security contexts
    context_type_get(3) - Routines to manipulate SELinux security contexts
    context_type_set(3) - Routines to manipulate SELinux security contexts
    context_user_get(3) - Routines to manipulate SELinux security contexts
    context_user_set(3) - Routines to manipulate SELinux security contexts
    continue(1p) - continue for, while, or until loop
    convertquota(8) - convert quota from old file format to new one
    copy_file_range(2) - Copy a range of data from one file to another
    copysign(3) - copy sign of a number
    copysign(3p) - number manipulation function
    copysignf(3) - copy sign of a number
    copysignf(3p) - number manipulation function
    copysignl(3) - copy sign of a number
    copysignl(3p) - number manipulation function
    copywin(3x) - overlay and manipulate overlapped curses windows
    core(5) - core dump file
    coredump.conf(5) - Core dump storage configuration files
    coredump.conf.d(5) - Core dump storage configuration files
    coredumpctl(1) - Retrieve and process saved core dumps and metadata
    coreutils(1) - single binary for coreutils programs
    cos(3) - cosine function
    cos(3p) - cosine function
    cosf(3) - cosine function
    cosf(3p) - cosine function
    cosh(3) - hyperbolic cosine function
    cosh(3p) - hyperbolic cosine functions
    coshf(3) - hyperbolic cosine function
    coshf(3p) - hyperbolic cosine functions
    coshl(3) - hyperbolic cosine function
    coshl(3p) - hyperbolic cosine functions
    cosl(3) - cosine function
    cosl(3p) - cosine function
    cp(1) - copy files and directories
    cp(1p) - copy files
    cp1251(7) - CP 1251 character set encoded in octal, decimal, and hexadecimal
    cp1252(7) - CP 1252 character set encoded in octal, decimal, and hexadecimal
    cpio.h(0p) - cpio archive values
    cpow(3) - complex power function
    cpow(3p) - complex power functions
    cpowf(3) - complex power function
    cpowf(3p) - complex power functions
    cpowl(3) - complex power function
    cpowl(3p) - complex power functions
    cpp(1) - The C Preprocessor
    cproj(3) - project into Riemann Sphere
    cproj(3p) - complex projection functions
    cprojf(3) - project into Riemann Sphere
    cprojf(3p) - complex projection functions
    cprojl(3) - project into Riemann Sphere
    cprojl(3p) - complex projection functions
    CPU_ALLOC(3) - macros for manipulating CPU sets
    cpu_alloc(3) - macros for manipulating CPU sets
    CPU_ALLOC_SIZE(3) - macros for manipulating CPU sets
    cpu_alloc_size(3) - macros for manipulating CPU sets
    CPU_AND(3) - macros for manipulating CPU sets
    cpu_and(3) - macros for manipulating CPU sets
    CPU_AND_S(3) - macros for manipulating CPU sets
    cpu_and_s(3) - macros for manipulating CPU sets
    CPU_CLR(3) - macros for manipulating CPU sets
    cpu_clr(3) - macros for manipulating CPU sets
    CPU_CLR_S(3) - macros for manipulating CPU sets
    cpu_clr_s(3) - macros for manipulating CPU sets
    CPU_COUNT(3) - macros for manipulating CPU sets
    cpu_count(3) - macros for manipulating CPU sets
    CPU_COUNT_S(3) - macros for manipulating CPU sets
    cpu_count_s(3) - macros for manipulating CPU sets
    CPU_EQUAL(3) - macros for manipulating CPU sets
    cpu_equal(3) - macros for manipulating CPU sets
    CPU_EQUAL_S(3) - macros for manipulating CPU sets
    cpu_equal_s(3) - macros for manipulating CPU sets
    CPU_FREE(3) - macros for manipulating CPU sets
    cpu_free(3) - macros for manipulating CPU sets
    cpuid(4) - x86 CPUID access device
    CPU_ISSET(3) - macros for manipulating CPU sets
    cpu_isset(3) - macros for manipulating CPU sets
    CPU_ISSET_S(3) - macros for manipulating CPU sets
    cpu_isset_s(3) - macros for manipulating CPU sets
    CPU_OR(3) - macros for manipulating CPU sets
    cpu_or(3) - macros for manipulating CPU sets
    CPU_OR_S(3) - macros for manipulating CPU sets
    cpu_or_s(3) - macros for manipulating CPU sets
    CPU_SET(3) - macros for manipulating CPU sets
    cpu_set(3) - macros for manipulating CPU sets
    cpuset(7) - confine processes to processor and memory node subsets
    CPU_SET_S(3) - macros for manipulating CPU sets
    cpu_set_s(3) - macros for manipulating CPU sets
    CPU_XOR(3) - macros for manipulating CPU sets
    cpu_xor(3) - macros for manipulating CPU sets
    CPU_XOR_S(3) - macros for manipulating CPU sets
    cpu_xor_s(3) - macros for manipulating CPU sets
    CPU_ZERO(3) - macros for manipulating CPU sets
    cpu_zero(3) - macros for manipulating CPU sets
    CPU_ZERO_S(3) - macros for manipulating CPU sets
    cpu_zero_s(3) - macros for manipulating CPU sets
    crash(8) - Analyze Linux crash dump data or a live system
    creal(3) - get real part of a complex number
    creal(3p) - complex real functions
    crealf(3) - get real part of a complex number
    crealf(3p) - complex real functions
    creall(3) - get real part of a complex number
    creall(3p) - complex real functions
    creat(2) - open and possibly create a file
    creat(3p) - create a new file or rewrite an existing one
    create_module(2) - create a loadable module entry
    credentials(7) - process identifiers
    cron(8) - daemon to execute scheduled commands
    crond(8) - daemon to execute scheduled commands
    cronnext(1) - time of next job cron will execute
    crontab(1) - maintains crontab files for individual users
    crontab(1p) - schedule periodic background work
    crontab(5) - files used to schedule the execution of programs
    crypt(3) - password and data encryption
    crypt(3p) - string encoding function (CRYPT)
    crypt_r(3) - password and data encryption
    cryptsetup-reencrypt(8) - tool for offline LUKS device re-encryption
    cryptsetup(8) - manage plain dm-crypt and LUKS encrypted volumes
    csin(3) - complex sine function
    csin(3p) - complex sine functions
    csinf(3) - complex sine function
    csinf(3p) - complex sine functions
    csinh(3) - complex hyperbolic sine
    csinh(3p) - complex hyperbolic sine functions
    csinhf(3) - complex hyperbolic sine
    csinhf(3p) - complex hyperbolic sine functions
    csinhl(3) - complex hyperbolic sine
    csinhl(3p) - complex hyperbolic sine functions
    csinl(3) - complex sine function
    csinl(3p) - complex sine functions
    csplit(1) - split a file into sections determined by context lines
    csplit(1p) - split files based on context
    csqrt(3) - complex square root
    csqrt(3p) - complex square root functions
    csqrtf(3) - complex square root
    csqrtf(3p) - complex square root functions
    csqrtl(3) - complex square root
    csqrtl(3p) - complex square root functions
    csum(8) - checksum update action
    csysdig(8) -
    ctags(1p) - create a tags file (DEVELOPMENT, FORTRAN)
    ctan(3) - complex tangent function
    ctan(3p) - complex tangent functions
    ctanf(3) - complex tangent function
    ctanf(3p) - complex tangent functions
    ctanh(3) - complex hyperbolic tangent
    ctanh(3p) - complex hyperbolic tangent functions
    ctanhf(3) - complex hyperbolic tangent
    ctanhf(3p) - complex hyperbolic tangent functions
    ctanhl(3) - complex hyperbolic tangent
    ctanhl(3p) - complex hyperbolic tangent functions
    ctanl(3) - complex tangent function
    ctanl(3p) - complex tangent functions
    ctermid(3) - get controlling terminal name
    ctermid(3p) - generate a pathname for the controlling terminal
    ctime(3) - transform date and time to broken-down time or ASCII
    ctime(3p) - convert a time value to a date and time string
    ctime_r(3) - transform date and time to broken-down time or ASCII
    ctime_r(3p) - convert a time value to a date and time string
    ctrlaltdel(8) - set the function of the Ctrl-Alt-Del combination
    ctstat(8) - unified linux network statistics
    ctype.h(0p) - character types
    cups-config(1) - get cups api, compiler, directory, and link information.
    cups-files.conf(5) - file and directory configuration file for cups
    cups-lpd(8) - receive print jobs and report printer status to lpd clients
    cups-snmp(8) - cups snmp backend
    cups-snmp.conf(5) - snmp configuration file for cups
    cups(1) - a standards-based, open source printing system
    cupsaccept(8) - accept/reject jobs sent to a destination
    cupsaddsmb(8) - export printers to samba for windows clients
    cupsctl(8) - configure cupsd.conf options
    cupsd-helper(8) - cupsd helper programs
    cupsd-logs(5) - cupsd log files (access_log, error_log, and page_log)
    cupsd(8) - cups scheduler
    cupsd.conf(5) - server configuration file for cups
    cupsdisable(8) - stop/start printers and classes
    cupsenable(8) - stop/start printers and classes
    cupsfilter(8) - convert a file to another format using cups filters
    cupstestdsc(1) - test conformance of postscript files (deprecated)
    cupstestppd(1) - test conformance of ppd files
    curs_addch(3x) - add a character (with attributes) to a curses window, then advance the cursor
    curs_addchstr(3x) - add a string of characters (and attributes) to a curses window
    curs_addstr(3x) - add a string of characters to a curses window and advance cursor
    curs_add_wch(3x) - add a complex character and rendition to a curses window, then advance the cursor
    curs_add_wchstr(3x) - add an array of complex characters (and attributes) to a curses window
    curs_addwstr(3x) - add a string of wide characters to a curses window and advance cursor
    curs_attr(3x) - curses character and window attribute control routines
    curs_beep(3x) - curses bell and screen flash routines
    curs_bkgd(3x) - curses window background manipulation routines
    curs_bkgrnd(3x) - curses window complex background manipulation routines
    curs_border(3x) - create curses borders, horizontal and vertical lines
    curs_border_set(3x) - create curses borders or lines using complex characters and renditions
    curs_clear(3x) - clear all or part of a curses window
    curs_color(3x) - curses color manipulation routines
    curscr(3x) - curses global variables
    curs_delch(3x) - delete character under the cursor in a curses window
    curs_deleteln(3x) - delete and insert lines in a curses window
    curses_version(3x) - miscellaneous curses extensions
    curs_extend(3x) - miscellaneous curses extensions
    curs_getcchar(3x) - Get a wide character string and rendition from a cchar_t or set a cchar_t from a wide-character string
    curs_getch(3x) - get (or push back) characters from curses terminal keyboard
    curs_getstr(3x) - accept character strings from curses terminal keyboard
    curs_get_wch(3x) - get (or push back) a wide character from curses terminal keyboard
    curs_get_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    curs_getyx(3x) - get curses cursor and window coordinates
    curs_inch(3x) - get a character and attributes from a curses window
    curs_inchstr(3x) - get a string of characters (and attributes) from a curses window
    curs_initscr(3x) - curses screen initialization and manipulation routines
    curs_inopts(3x) - curses input options
    curs_insch(3x) - insert a character before cursor in a curses window
    curs_insstr(3x) - insert string before cursor in a curses window
    curs_instr(3x) - get a string of characters from a curses window
    curs_ins_wch(3x) - insert a complex character and rendition into a window
    curs_ins_wstr(3x) - insert a wide-character string into a curses window
    curs_in_wch(3x) - extract a complex character and rendition from a window
    curs_in_wchstr(3x) - get an array of complex characters and renditions from a curses window
    curs_inwstr(3x) - get a string of wchar_t characters from a curses window
    curs_kernel(3x) - low-level curses routines
    curs_legacy(3x) - get curses cursor and window coordinates, attributes
    curs_memleaks(3x) - curses memory-leak checking
    curs_mouse(3x) - mouse interface through curses
    curs_move(3x) - move curses window cursor
    curs_opaque(3x) - curses window properties
    curs_outopts(3x) - curses output options
    curs_overlay(3x) - overlay and manipulate overlapped curses windows
    curs_pad(3x) - create and display curses pads
    curs_print(3x) - ship binary data to printer
    curs_printw(3x) - print formatted output in curses windows
    curs_refresh(3x) - refresh curses windows and lines
    curs_scanw(3x) - convert formatted input from a curses window
    curs_scr_dump(3x) - read (write) a curses screen from (to) a file
    curs_scroll(3x) - scroll a curses window
    curs_set(3x) - low-level curses routines
    curs_slk(3x) - curses soft label routines
    curs_sp_funcs(3x) - curses screen-pointer extension
    curs_termattrs(3x) - curses environment query routines
    curs_termcap(3x) - direct curses interface to the terminfo capability database
    curs_terminfo(3x) - curses interfaces to terminfo database
    curs_threads(3x) - curses thread support
    curs_touch(3x) - curses refresh control routines
    curs_trace(3x) - curses debugging routines
    curs_util(3x) - miscellaneous curses utility routines
    curs_variables(3x) - curses global variables
    curs_window(3x) - create curses windows
    cur_term(3x) - curses terminfo global variables
    curvetun(8) - a lightweight curve25519 ip4/6 tunnel
    cuserid(3) - get username
    customizable_types(5) - The SELinux customizable types configuration file
    cut(1) - remove sections from each line of files
    cut(1p) - cut out selected fields of each line of a file
    cxref(1p) - language program cross-reference table (DEVELOPMENT)

top
    daemon(3) - run in the background
    daemon(7) - Writing and packaging system daemons
    dane_cert_type_name(3) - API function
    dane_cert_usage_name(3) - API function
    dane_match_type_name(3) - API function
    dane_query_data(3) - API function
    dane_query_deinit(3) - API function
    dane_query_entries(3) - API function
    dane_query_status(3) - API function
    dane_query_tlsa(3) - API function
    dane_query_to_raw_tlsa(3) - API function
    dane_raw_tlsa(3) - API function
    dane_state_deinit(3) - API function
    dane_state_init(3) - API function
    dane_state_set_dlv_file(3) - API function
    dane_strerror(3) - API function
    danetool(1) - GnuTLS DANE tool
    dane_verification_status_print(3) - API function
    dane_verify_crt(3) - API function
    dane_verify_crt_raw(3) - API function
    dane_verify_session_crt(3) - API function
    dash(1) - command interpreter (shell)
    data_ahead(3x) - test for off-screen data in given forms
    data_behind(3x) - test for off-screen data in given forms
    date(1) - print or set the system date and time
    date(1p) - write the date and time
    daylight(3) - initialize time conversion information
    daylight(3p) - daylight savings time flag
    db(3) - database access methods
    dbm_clearerr(3p) - database functions
    dbm_close(3p) - database functions
    dbm_delete(3p) - database functions
    dbm_error(3p) - database functions
    dbm_fetch(3p) - database functions
    dbm_firstkey(3p) - database functions
    dbm_nextkey(3p) - database functions
    dbm_open(3p) - database functions
    dbm_store(3p) - database functions
    dbopen(3) - database access methods
    dbpmda(1) - debugger for Performance Co-Pilot PMDAs
    dbprobe(1) - database response time and availability information
    dcgettext(3) - translate message
    dcngettext(3) - translate message and choose plural form
    dd(1) - convert and copy a file
    dd(1p) - convert and copy a file
    ddp(7) - Linux AppleTalk protocol implementation
    deallocvt(1) - deallocate unused virtual consoles
    deb-buildinfo(5) - Debian build information file format
    deb-changelog(5) - dpkg source packages' changelog file format
    deb-changes(5) - Debian changes file format
    deb-conffiles(5) - package conffiles
    deb-control(5) - Debian binary packages' master control file format
    deb-extra-override(5) - Debian archive extra override file
    deb-old(5) - old style Debian binary package format
    deb-origin(5) - Vendor-specific information files
    deb-override(5) - Debian archive override file
    deb-postinst(5) - package post-installation maintainer script
    deb-postrm(5) - package post-removal maintainer script
    deb-preinst(5) - package pre-installation maintainer script
    deb-prerm(5) - package pre-removal maintainer script
    deb-shlibs(5) - Debian shared library information file
    deb-split(5) - Debian multi-part binary package format
    deb-src-control(5) - Debian source packages' master control file format
    deb-src-files(5) - Debian distribute files format
    deb-src-rules(5) - Debian source package rules file
    deb-substvars(5) - Debian source substitution variables
    deb-symbols(5) - Debian's extended shared library information file
    deb-triggers(5) - package triggers
    deb-version(7) - Debian package version number format
    deb(5) - Debian binary package format
    deb822(5) - Debian RFC822 control data format
    debhelper-obsolete-compat(7) - List of no longer supported compat levels
    debhelper(7) - the debhelper tool suite
    debugfs(8) - ext2/ext3/ext4 file system debugger
    debuginfo-install(1) - install debuginfo packages and their dependencies
    default_colors(3x) - use terminal's default colors
    default_contexts(5) - The SELinux default contexts configuration file
    default_type(5) - The SELinux default type configuration file
    define_key(3x) - define a keycode
    def_prog_mode(3x) - low-level curses routines
    def_shell_mode(3x) - low-level curses routines
    delay_output(3x) - miscellaneous curses utility routines
    delch(3x) - delete character under the cursor in a curses window
    del_curterm(3x) - curses interfaces to terminfo database
    deleteln(3x) - delete and insert lines in a curses window
    delete_module(2) - unload a kernel module
    delpart(8) - tell the kernel to forget about a partition
    delscreen(3x) - curses screen initialization and manipulation routines
    delta(1p) - make a delta (change) to an SCCS file (DEVELOPMENT)
    delwin(3x) - create curses windows
    depmod(8) - Generate modules.dep and map files.
    depmod.d(5) - Configuration directory for depmod
    derwin(3x) - create curses windows
    des_crypt(3) - fast DES encryption
    DES_FAILED(3) - fast DES encryption
    des_failed(3) - fast DES encryption
    des_setparity(3) - fast DES encryption
    devlink-dev(8) - devlink device configuration
    devlink-monitor(8) - state monitoring
    devlink-port(8) - devlink port configuration
    devlink-region(8) - devlink address region access
    devlink-resource(8) - devlink device resource configuration
    devlink-sb(8) - devlink shared buffer configuration
    devlink(8) - Devlink tool
    df(1) - report file system disk space usage
    df(1p) - report free disk space
    dgettext(3) - translate message
    dh(1) - debhelper command sequencer
    dh_auto_build(1) - automatically builds a package
    dh_auto_clean(1) - automatically cleans up after a build
    dh_auto_configure(1) - automatically configure a package prior to building
    dh_auto_install(1) - automatically runs make install or similar
    dh_auto_test(1) - automatically runs a package's test suites
    dh_bugfiles(1) - install bug reporting customization files into package build directories
    dh_builddeb(1) - build Debian binary packages
    dh_clean(1) - clean up package build directories
    dh_compress(1) - compress files and fix symlinks in package build directories
    dh_dwz(1) - optimize DWARF debug information in ELF binaries via dwz
    dh_fixperms(1) - fix permissions of files in package build directories
    dh_gconf(1) - install GConf defaults files and register schemas
    dh_gencontrol(1) - generate and install control file
    dh_icons(1) - Update caches of Freedesktop icons
    dh_install(1) - install files into package build directories
    dh_installcatalogs(1) - install and register SGML Catalogs
    dh_installchangelogs(1) - install changelogs into package build directories
    dh_installcron(1) - install cron scripts into etc/cron.*
    dh_installdeb(1) - install files into the DEBIAN directory
    dh_installdebconf(1) - install files used by debconf in package build directories
    dh_installdirs(1) - create subdirectories in package build directories
    dh_installdocs(1) - install documentation into package build directories
    dh_installemacsen(1) - register an Emacs add on package
    dh_installexamples(1) - install example files into package build directories
    dh_installgsettings(1) - install GSettings overrides and set dependencies
    dh_installifupdown(1) - install if-up and if-down hooks
    dh_installinfo(1) - install info files
    dh_installinit(1) - install service init files into package build directories
    dh_installinitramfs(1) - install initramfs hooks and setup maintscripts
    dh_installlogcheck(1) - install logcheck rulefiles into etc/logcheck/
    dh_installlogrotate(1) - install logrotate config files
    dh_installman(1) - install man pages into package build directories
    dh_installmanpages(1) - old-style man page installer (deprecated)
    dh_installmenu(1) - install Debian menu files into package build directories
    dh_installmime(1) - install mime files into package build directories
    dh_installmodules(1) - register kernel modules
    dh_installpam(1) - install pam support files
    dh_installppp(1) - install ppp ip-up and ip-down files
    dh_installsystemd(1) - install systemd unit files
    dh_installsystemduser(1) - install systemd unit files
    dh_installudev(1) - install udev rules files
    dh_installwm(1) - register a window manager
    dh_installxfonts(1) - register X fonts
    dh_link(1) - create symlinks in package build directories
    dh_lintian(1) - install lintian override files into package build directories
    dh_listpackages(1) - list binary packages debhelper will act on
    dh_makeshlibs(1) - automatically create shlibs file and call dpkg-gensymbols
    dh_md5sums(1) - generate DEBIAN/md5sums file
    dh_missing(1) - check for missing files
    dh_movefiles(1) - move files out of debian/tmp into subpackages
    dh_perl(1) - calculates Perl dependencies and cleans up after MakeMaker
    dh_prep(1) - perform cleanups in preparation for building a binary package
    dh_shlibdeps(1) - calculate shared library dependencies
    dh_strip(1) - strip executables, shared libraries, and some static libraries
    dh_systemd_enable(1) - enable/disable systemd unit files
    dh_systemd_start(1) - start/stop/restart systemd unit files
    dh_testdir(1) - test directory before building Debian package
    dh_testroot(1) - ensure that a package is built with necessary level of root permissions
    dh_ucf(1) - register configuration files with ucf
    dh_update_autotools_config(1) - Update autotools config files
    dh_usrlocal(1) - migrate usr/local directories to maintainer scripts
    diff(1) - compare files line by line
    diff(1p) - compare two files
    diff3(1) - compare three files line by line
    difftime(3) - calculate time difference
    difftime(3p) - compute the difference between two calendar time values
    dir(1) - list directory contents
    dircolors(1) - color setup for ls
    dir_colors(5) - configuration file for dircolors(1)
    dirent.h(0p) - format of directory entries
    dirfd(3) - get directory stream file descriptor
    dirfd(3p) - extract the file descriptor used by a DIR stream
    dirname(1) - strip last component from file name
    dirname(1p) - return the directory portion of a pathname
    dirname(3) - parse pathname components
    dirname(3p) - report the parent directory name of a file pathname
    ditroff(7) - classical device-independent roff
    div(3) - compute quotient and remainder of an integer division
    div(3p) - compute the quotient and remainder of an integer division
    dladdr(3) - translate address to symbolic information
    dladdr1(3) - translate address to symbolic information
    dlclose(3) - open and close a shared object
    dlclose(3p) - close a symbol table handle
    dlerror(3) - obtain error diagnostic for functions in the dlopen API
    dlerror(3p) - get diagnostic information
    dlfcn.h(0p) - dynamic linking
    dlinfo(3) - obtain information about a dynamically loaded object
    dl_iterate_phdr(3) - walk through list of shared objects
    dlltool(1) - Create files needed to build and use DLLs.
    dlmopen(3) - open and close a shared object
    dlopen(3) - open and close a shared object
    dlopen(3p) - open a symbol table handle
    dlsym(3) - obtain address of a symbol in a shared object or executable
    dlsym(3p) - get the address of a symbol from a symbol table handle
    dlvsym(3) - obtain address of a symbol in a shared object or executable
    dmesg(1) - print or control the kernel ring buffer
    dmsetup(8) - low level logical volume management
    dmstats(8) - mapper statistics management
    dn_comp(3) - resolver routines
    dn_expand(3) - resolver routines
    dngettext(3) - translate message and choose plural form
    dnsdomainname(1) - show or set the system's host name
    dnssec-trust-anchors.d(5) - DNSSEC trust anchor configuration files
    domainname(1) - show or set the system's host name
    dot(1p) - execute commands in the current environment
    do_tracepoint(3) - LTTng user space tracing
    doupdate(3x) - refresh curses windows and lines
    dpkg-architecture(1) - set and determine the architecture for package building
    dpkg-buildflags(1) - returns build flags to use during package build
    dpkg-buildpackage(1) - build binary or source packages from sources
    dpkg-checkbuilddeps(1) - check build dependencies and conflicts
    dpkg-deb(1) - Debian package archive (.deb) manipulation tool
    dpkg-distaddfile(1) - add entries to debian/files
    dpkg-divert(1) - override a package's version of a file
    dpkg-genbuildinfo(1) - generate Debian .buildinfo files
    dpkg-genchanges(1) - generate Debian .changes files
    dpkg-gencontrol(1) - generate Debian control files
    dpkg-gensymbols(1) - generate symbols files (shared library dependency information)
    dpkg-maintscript-helper(1) - works around known dpkg limitations in maintainer scripts
    dpkg-mergechangelogs(1) - 3-way merge of debian/changelog files
    dpkg-name(1) - rename Debian packages to full package names
    dpkg-parsechangelog(1) - parse Debian changelog files
    dpkg-query(1) - a tool to query the dpkg database
    dpkg-scanpackages(1) - create Packages index files
    dpkg-scansources(1) - create Sources index files
    dpkg-shlibdeps(1) - generate shared library substvar dependencies
    dpkg-source(1) - Debian source package (.dsc) manipulation tool
    dpkg-split(1) - Debian package archive split/join tool
    dpkg-statoverride(1) - override ownership and mode of files
    dpkg-trigger(1) - a package trigger utility
    dpkg-vendor(1) - queries information about distribution vendors
    dpkg(1) - package manager for Debian
    dpkg.cfg(5) - dpkg configuration file
    dprintf(3) - formatted output conversion
    dprintf(3p) - print formatted output
    dracut-catimages(8) - creates initial ramdisk image by concatenating images
    dracut(8) - low-level tool for generating an initramfs/initrd image
    dracut.bootup(7) - boot ordering in the initramfs
    dracut.cmdline(7) - dracut kernel command line options
    dracut.conf(5) - configuration file(s) for dracut
    dracut.modules(7) - dracut modules
    drand48(3) - generate uniformly distributed pseudo-random numbers
    drand48(3p) - random numbers
    drand48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    drem(3) - floating-point remainder function
    dremf(3) - floating-point remainder function
    dreml(3) - floating-point remainder function
    drr(8) - deficit round robin scheduler
    dsc(5) - Debian source packages' control file format
    dselect(1) - Debian package management frontend
    dselect.cfg(5) - dselect configuration file
    dsp56k(4) - DSP56001 interface device
    dtrace(1) - Dtrace compatible user application static probe generation tool.
    du(1) - estimate file space usage
    du(1p) - estimate file space usage
    dump-acct(8) - print an acct/pacct file in human-readable format
    dump-utmp(8) - print a utmp file in human-readable format
    dumpe2fs(8) - dump ext2/ext3/ext4 filesystem information
    dumpkeys(1) - dump keyboard translation tables
    dup(2) - duplicate a file descriptor
    dup(3p) - duplicate an open file descriptor
    dup2(2) - duplicate a file descriptor
    dup2(3p) - duplicate an open file descriptor
    dup3(2) - duplicate a file descriptor
    dup_field(3x) - create and destroy form fields
    duplocale(3) - duplicate a locale object
    duplocale(3p) - duplicate a locale object
    dupwin(3x) - create curses windows
    dynamic_field_info(3x) - retrieve field characteristics
    dysize(3) - get number of days for a given year

top
    e2freefrag(8) - report free space fragmentation information
    e2fsck(8) - check a Linux ext2/ext3/ext4 file system
    e2fsck.conf(5) - Configuration file for e2fsck
    e2image(8) - Save critical ext2/ext3/ext4 filesystem metadata to a file
    e2label(8) - Change the label on an ext2/ext3/ext4 filesystem
    e2mmpstatus(8) - Check MMP status of an ext4 filesystem
    e2undo(8) - Replay an undo log for an ext2/ext3/ext4 filesystem
    e4crypt(8) - ext4 filesystem encryption utility
    e4defrag(8) - online defragmenter for ext4 filesystem
    eaccess(3) - check effective user's permissions for a file
    ecb_crypt(3) - fast DES encryption
    echo(1) - display a line of text
    echo(1p) - write arguments to standard output
    echo(3x) - curses input options
    echochar(3x) - add a character (with attributes) to a curses window, then advance the cursor
    echo_wchar(3x) - add a complex character and rendition to a curses window, then advance the cursor
    ecvt(3) - convert a floating-point number to a string
    ecvt_r(3) - convert a floating-point number to a string
    ed(1p) - edit text
    edata(3) - end of program segments
    edquota(8) - edit user quotas
    egrep(1) - print lines that match patterns
    eject(1) - eject removable media
    elf(5) - format of Executable and Linking Format (ELF) files
    elfedit(1) - Update the ELF header of ELF files.
    ematch(8) - extended matches for use with "basic" or "flow" filters
    encrypt(3) - encrypt 64-bit messages
    encrypt(3p) - encoding function (CRYPT)
    encrypt_r(3) - encrypt 64-bit messages
    end(3) - end of program segments
    endaliasent(3) - read an alias entry
    endfsent(3) - handle fstab entries
    endgrent(3) - get group file entry
    endgrent(3p) - group database entry functions
    endhostent(3) - get network host entry
    endhostent(3p) - network host database functions
    endian(3) - convert values between host and big-/little-endian byte order
    endmntent(3) - get filesystem descriptor file entry
    endnetent(3) - get network entry
    endnetent(3p) - network database functions
    endnetgrent(3) - handle network group entries
    endprotoent(3) - get protocol entry
    endprotoent(3p) - network protocol database functions
    endpwent(3) - get password file entry
    endpwent(3p) - user database functions
    endrpcent(3) - get RPC entry
    endservent(3) - get service entry
    endservent(3p) - network services database functions
    endspent(3) - get shadow password file entry
    endttyent(3) - get ttys file entry
    endusershell(3) - get permitted user shells
    endutent(3) - access utmp file entries
    endutxent(3) - access utmp file entries
    endutxent(3p) - user accounting database functions
    endwin(3x) - curses screen initialization and manipulation routines
    env(1) - run a program in a modified environment
    env(1p) - set the environment for command invocation
    environ(3p) - array of character pointers to the environment strings
    environ(7) - user environment
    environment(5) - the environment variables config files
    environment.d(5) - Definition of user session environment
    envsubst(1) - substitutes environment variables in shell format strings
    envz(3) - environment string support
    envz_add(3) - environment string support
    envz_entry(3) - environment string support
    envz_get(3) - environment string support
    envz_merge(3) - environment string support
    envz_remove(3) - environment string support
    envz_strip(3) - environment string support
    epoll(7) - I/O event notification facility
    epoll_create(2) - open an epoll file descriptor
    epoll_create1(2) - open an epoll file descriptor
    epoll_ctl(2) - control interface for an epoll file descriptor
    epoll_pwait(2) - wait for an I/O event on an epoll file descriptor
    epoll_wait(2) - wait for an I/O event on an epoll file descriptor
    eqn(1) - format equations for troff or MathML
    eqn2graph(1) - convert an EQN equation into a cropped image
    erand48(3) - generate uniformly distributed pseudo-random numbers
    erand48(3p) - random numbers
    erand48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    erase(3x) - clear all or part of a curses window
    erasechar(3x) - curses environment query routines
    erasewchar(3x) - curses environment query routines
    erf(3) - error function
    erf(3p) - error functions
    erfc(3) - complementary error function
    erfc(3p) - complementary error functions
    erfcf(3) - complementary error function
    erfcf(3p) - complementary error functions
    erfcl(3) - complementary error function
    erfcl(3p) - complementary error functions
    erff(3) - error function
    erff(3p) - error functions
    erfl(3) - error function
    erfl(3p) - error functions
    err(3) - formatted error messages
    errno(3) - number of last error
    errno(3p) - error return value
    errno.h(0p) - system error numbers
    error(3) - glibc error reporting functions
    error::buildid(7stap) - build-id verification failures
    error::dwarf(7stap) - dwarf debuginfo quality problems
    error::fault(7stap) - memory access faults
    error::inode-uprobes(7stap) - limitations of inode-uprobes
    error::pass1(7stap) - systemtap pass-1 errors
    error::pass2(7stap) - systemtap pass-2 errors
    error::pass3(7stap) - systemtap pass-3 errors
    error::pass4(7stap) - systemtap pass-4 errors
    error::pass5(7stap) - systemtap pass-5 errors
    error::process-tracking(7stap) - process-tracking facilities are not available
    error::reporting(7stap) - systemtap error reporting
    error::sdt(7stap) - <sys/sdt.h> marker failures
    error_at_line(3) - glibc error reporting functions
    error_message_count(3) - glibc error reporting functions
    error_one_per_line(3) - glibc error reporting functions
    error_print_progname(3) - glibc error reporting functions
    errx(3) - formatted error messages
    ESCDELAY(3x) - curses global variables
    etext(3) - end of program segments
    ETF(8) - Earliest TxTime First (ETF) Qdisc
    ether_aton(3) - Ethernet address manipulation routines
    ether_aton_r(3) - Ethernet address manipulation routines
    ether_hostton(3) - Ethernet address manipulation routines
    ether_line(3) - Ethernet address manipulation routines
    ether_ntoa(3) - Ethernet address manipulation routines
    ether_ntoa_r(3) - Ethernet address manipulation routines
    ether_ntohost(3) - Ethernet address manipulation routines
    ethers(5) - Ethernet address to IP number database
    ethtool(8) - query or control network driver and hardware settings
    euidaccess(3) - check effective user's permissions for a file
    eval(1p) - construct command by concatenating arguments
    evbuffer_add(3) - execute a function when a specific event occurs
    evbuffer_add_buffer(3) - execute a function when a specific event occurs
    evbuffer_add_printf(3) - execute a function when a specific event occurs
    evbuffer_add_vprintf(3) - execute a function when a specific event occurs
    evbuffer_drain(3) - execute a function when a specific event occurs
    evbuffer_find(3) - execute a function when a specific event occurs
    evbuffer_free(3) - execute a function when a specific event occurs
    evbuffer_new(3) - execute a function when a specific event occurs
    evbuffer_read(3) - execute a function when a specific event occurs
    evbuffer_readline(3) - execute a function when a specific event occurs
    evbuffer_write(3) - execute a function when a specific event occurs
    evdns(3) - asynchronous functions for DNS resolution.
    evdns_clear_nameservers_and_suspend(3) - asynchronous functions for DNS resolution.
    evdns_config_windows_nameservers(3) - asynchronous functions for DNS resolution.
    evdns_count_nameservers(3) - asynchronous functions for DNS resolution.
    evdns_err_to_string(3) - asynchronous functions for DNS resolution.
    evdns_init(3) - asynchronous functions for DNS resolution.
    evdns_nameserver_add(3) - asynchronous functions for DNS resolution.
    evdns_nameserver_ip_add(3) - asynchronous functions for DNS resolution.
    evdns_resolv_conf_parse(3) - asynchronous functions for DNS resolution.
    evdns_resolve_ipv4(3) - asynchronous functions for DNS resolution.
    evdns_resolve_reverse(3) - asynchronous functions for DNS resolution.
    evdns_resume(3) - asynchronous functions for DNS resolution.
    evdns_search_add(3) - asynchronous functions for DNS resolution.
    evdns_search_clear(3) - asynchronous functions for DNS resolution.
    evdns_search_ndots_set(3) - asynchronous functions for DNS resolution.
    evdns_set_log_fn(3) - asynchronous functions for DNS resolution.
    evdns_shutdown(3) - asynchronous functions for DNS resolution.
    event(3) - execute a function when a specific event occurs
    event_add(3) - execute a function when a specific event occurs
    event_base_dispatch(3) - execute a function when a specific event occurs
    event_base_free(3) - execute a function when a specific event occurs
    event_base_loop(3) - execute a function when a specific event occurs
    event_base_loopbreak(3) - execute a function when a specific event occurs
    event_base_loopexit(3) - execute a function when a specific event occurs
    event_base_once(3) - execute a function when a specific event occurs
    event_base_set(3) - execute a function when a specific event occurs
    event_del(3) - execute a function when a specific event occurs
    event_dispatch(3) - execute a function when a specific event occurs
    eventfd(2) - create a file descriptor for event notification
    eventfd2(2) - create a file descriptor for event notification
    eventfd_read(3) - create a file descriptor for event notification
    eventfd_write(3) - create a file descriptor for event notification
    event_init(3) - execute a function when a specific event occurs
    event_initialized(3) - execute a function when a specific event occurs
    event_loop(3) - execute a function when a specific event occurs
    event_loopbreak(3) - execute a function when a specific event occurs
    event_loopexit(3) - execute a function when a specific event occurs
    event_once(3) - execute a function when a specific event occurs
    event_pending(3) - execute a function when a specific event occurs
    event_priority_init(3) - execute a function when a specific event occurs
    event_priority_set(3) - execute a function when a specific event occurs
    event_set(3) - execute a function when a specific event occurs
    evhttp_bind_socket(3) - execute a function when a specific event occurs
    evhttp_free(3) - execute a function when a specific event occurs
    evhttp_new(3) - execute a function when a specific event occurs
    evtimer_add(3) - execute a function when a specific event occurs
    evtimer_del(3) - execute a function when a specific event occurs
    evtimer_initialized(3) - execute a function when a specific event occurs
    evtimer_pending(3) - execute a function when a specific event occurs
    evtimer_set(3) - execute a function when a specific event occurs
    ex(1p) - text editor
    exec(1p) - execute commands and open, close, or copy file descriptors
    exec(3) - execute a file
    exec(3p) - execute a file
    execl(3) - execute a file
    execl(3p) - execute a file
    execle(3) - execute a file
    execle(3p) - execute a file
    execlp(3) - execute a file
    execlp(3p) - execute a file
    execstack(8) - tool to set, clear, or query executable stack flag of ELF binaries and shared libraries
    execv(3) - execute a file
    execv(3p) - execute a file
    execve(2) - execute program
    execve(3p) - execute a file
    execveat(2) - execute program relative to a directory file descriptor
    execvp(3) - execute a file
    execvp(3p) - execute a file
    execvpe(3) - execute a file
    exit(1p) - cause the shell to exit
    exit(2) - terminate the calling process
    _Exit(2) - terminate the calling process
    _exit(2) - terminate the calling process
    exit(3) - cause normal process termination
    exit(3p) - terminate a process
    _Exit(3p) - terminate a process
    _exit(3p) - terminate a process
    exit_group(2) - exit all threads in a process
    exp(3) - base-e exponential function
    exp(3p) - exponential function
    exp10(3) - base-10 exponential function
    exp10f(3) - base-10 exponential function
    exp10l(3) - base-10 exponential function
    exp2(3) - base-2 exponential function
    exp2(3p) - exponential base 2 functions
    exp2f(3) - base-2 exponential function
    exp2f(3p) - exponential base 2 functions
    exp2l(3) - base-2 exponential function
    exp2l(3p) - exponential base 2 functions
    expand(1) - convert tabs to spaces
    expand(1p) - convert tabs to spaces
    expect(1) - programmed dialogue with interactive programs, Version 5
    expf(3) - base-e exponential function
    expf(3p) - exponential function
    expiry(1) - check and enforce password expiration policy
    expl(3) - base-e exponential function
    expl(3p) - exponential function
    explicit_bzero(3) - zero a byte string
    expm1(3) - exponential minus 1
    expm1(3p) - compute exponential functions
    expm1f(3) - exponential minus 1
    expm1f(3p) - compute exponential functions
    expm1l(3) - exponential minus 1
    expm1l(3p) - compute exponential functions
    export(1p) - set the export attribute for variables
    exportfs(8) - maintain table of exported NFS file systems
    exports(5) - NFS server export table
    expr(1) - evaluate expressions
    expr(1p) - evaluate arguments as an expression
    ext2(5) - the second extended file system
    ext3(5) - the second extended file system
    ext4(5) - the second extended file system
    extended_slk_color(3x) - curses soft label routines

top
    fabs(3) - absolute value of floating-point number
    fabs(3p) - absolute value function
    fabsf(3) - absolute value of floating-point number
    fabsf(3p) - absolute value function
    fabsl(3) - absolute value of floating-point number
    fabsl(3p) - absolute value function
    faccessat(2) - check user's permissions for a file
    faccessat(3p) - determine accessibility of a file relative to directory file descriptor
    factor(1) - factor numbers
    fadvise64(2) - predeclare an access pattern for file data
    fadvise64_64(2) - predeclare an access pattern for file data
    faillog(5) - login failure logging file
    faillog(8) - display faillog records or set login failure limits
    failsafe_context(5) - The SELinux fail safe context configuration file
    fallocate(1) - preallocate or deallocate space to a file
    fallocate(2) - manipulate file space
    false(1) - do nothing, unsuccessfully
    false(1p) - return false value
    fanotify(7) - monitoring filesystem events
    fanotify_init(2) - create and initialize fanotify group
    fanotify_mark(2) - add, remove, or modify an fanotify mark on a filesystem object
    fattach(2) - unimplemented system calls
    fattach(3p) - based file descriptor to a file in the file system name space (STREAMS)
    __fbufsize(3) - interfaces to stdio FILE structure
    fc(1p) - process the command history list
    fchdir(2) - change working directory
    fchdir(3p) - change working directory
    fchmod(2) - change permissions of a file
    fchmod(3p) - change mode of a file
    fchmodat(2) - change permissions of a file
    fchmodat(3p) - change mode of a file relative to directory file descriptor
    fchown(2) - change ownership of a file
    fchown(3p) - change owner and group of a file
    fchown32(2) - change ownership of a file
    fchownat(2) - change ownership of a file
    fchownat(3p) - change owner and group of a file relative to directory file descriptor
    fclose(3) - close a stream
    fclose(3p) - close a stream
    fcloseall(3) - close all open streams
    fcntl(2) - manipulate file descriptor
    fcntl(3p) - file control
    fcntl.h(0p) - file control options
    fcntl64(2) - manipulate file descriptor
    fcvt(3) - convert a floating-point number to a string
    fcvt_r(3) - convert a floating-point number to a string
    fd(4) - floppy disk device
    fdatasync(2) - synchronize a file's in-core state with storage device
    fdatasync(3p) - synchronize the data of a file (REALTIME)
    FD_CLR(3) - synchronous I/O multiplexing
    fd_clr(3) - synchronous I/O multiplexing
    FD_CLR(3p) - macros for synchronous I/O multiplexing
    fd_clr(3p) - macros for synchronous I/O multiplexing
    fdetach(2) - unimplemented system calls
    fdetach(3p) - based file descriptor (STREAMS)
    fdformat(8) - low-level format a floppy disk
    fdim(3) - positive difference
    fdim(3p) - point numbers
    fdimf(3) - positive difference
    fdimf(3p) - point numbers
    fdiml(3) - positive difference
    fdiml(3p) - point numbers
    fdisk(8) - manipulate disk partition table
    FD_ISSET(3) - synchronous I/O multiplexing
    fd_isset(3) - synchronous I/O multiplexing
    fdopen(3) - stream open functions
    fdopen(3p) - associate a stream with a file descriptor
    fdopendir(3) - open a directory
    fdopendir(3p) - open directory associated with file descriptor
    FD_SET(3) - synchronous I/O multiplexing
    fd_set(3) - synchronous I/O multiplexing
    fd_to_handle(3) - file handle operations
    FD_ZERO(3) - synchronous I/O multiplexing
    fd_zero(3) - synchronous I/O multiplexing
    feature_test_macros(7) - feature test macros
    feclearexcept(3) - floating-point rounding and exception handling
    feclearexcept(3p) - point exception
    fedabipkgdiff(1) - compare ABIs of Fedora packages
    fedisableexcept(3) - floating-point rounding and exception handling
    feenableexcept(3) - floating-point rounding and exception handling
    fegetenv(3) - floating-point rounding and exception handling
    fegetenv(3p) - point environment
    fegetexcept(3) - floating-point rounding and exception handling
    fegetexceptflag(3) - floating-point rounding and exception handling
    fegetexceptflag(3p) - point status flags
    fegetround(3) - floating-point rounding and exception handling
    fegetround(3p) - get and set current rounding direction
    feholdexcept(3) - floating-point rounding and exception handling
    feholdexcept(3p) - point environment
    fenv(3) - floating-point rounding and exception handling
    fenv.h(0p) - point environment
    feof(3) - check and reset stream status
    feof(3p) - of-file indicator on a stream
    feof_unlocked(3) - nonlocking stdio functions
    feraiseexcept(3) - floating-point rounding and exception handling
    feraiseexcept(3p) - point exception
    ferror(3) - check and reset stream status
    ferror(3p) - test error indicator on a stream
    ferror_unlocked(3) - nonlocking stdio functions
    fesetenv(3) - floating-point rounding and exception handling
    fesetenv(3p) - point environment
    fesetexceptflag(3) - floating-point rounding and exception handling
    fesetexceptflag(3p) - point status flags
    fesetround(3) - floating-point rounding and exception handling
    fesetround(3p) - set current rounding direction
    fetestexcept(3) - floating-point rounding and exception handling
    fetestexcept(3p) - point exception flags
    feupdateenv(3) - floating-point rounding and exception handling
    feupdateenv(3p) - point environment
    fexecve(3) - execute program specified via file descriptor
    fexecve(3p) - execute a file
    fflush(3) - flush a stream
    fflush(3p) - flush a stream
    fflush_unlocked(3) - nonlocking stdio functions
    ffs(3) - find first bit set in a word
    ffs(3p) - find first set bit
    ffsl(3) - find first bit set in a word
    ffsll(3) - find first bit set in a word
    fg(1p) - run jobs in the foreground
    fgconsole(1) - print the number of the active VT.
    fgetc(3) - input of characters and strings
    fgetc(3p) - get a byte from a stream
    fgetc_unlocked(3) - nonlocking stdio functions
    fgetfilecon(3) - get SELinux security context of a file
    fgetfilecon_raw(3) - get SELinux security context of a file
    fgetgrent(3) - get group file entry
    fgetgrent_r(3) - get group file entry reentrantly
    fgetpos(3) - reposition a stream
    fgetpos(3p) - get current file position information
    fgetpwent(3) - get password file entry
    fgetpwent_r(3) - get passwd file entry reentrantly
    fgets(3) - input of characters and strings
    fgets(3p) - get a string from a stream
    fgetspent(3) - get shadow password file entry
    fgetspent_r(3) - get shadow password file entry
    fgets_unlocked(3) - nonlocking stdio functions
    fgetwc(3) - read a wide character from a FILE stream
    fgetwc(3p) - character code from a stream
    fgetwc_unlocked(3) - nonlocking stdio functions
    fgetws(3) - read a wide-character string from a FILE stream
    fgetws(3p) - character string from a stream
    fgetws_unlocked(3) - nonlocking stdio functions
    fgetxattr(2) - retrieve an extended attribute value
    fgrep(1) - print lines that match patterns
    field_info(3x) - retrieve field characteristics
    field_just(3x) - retrieve field characteristics
    field_opts(3x) - set and get field options
    field_opts_off(3x) - set and get field options
    field_opts_on(3x) - set and get field options
    field_userptr(3x) - associate application data with a form field
    fifo(7) - first-in first-out special file, named pipe
    file-hierarchy(7) - File system hierarchy overview
    file(1) - determine file type
    file(1p) - determine file type
    filecap(8) - a program to see capabilities
    file_contexts(5) - userspace SELinux labeling interface and configuration file format for the file contexts backend
    file_contexts.homedirs(5) - userspace SELinux labeling interface and configuration file format for the file contexts backend
    file_contexts.local(5) - userspace SELinux labeling interface and configuration file format for the file contexts backend
    file_contexts.subs(5) - userspace SELinux labeling interface and configuration file format for the file contexts backend
    file_contexts.subs_dist(5) - userspace SELinux labeling interface and configuration file format for the file contexts backend
    filefrag(8) - report on file fragmentation
    fileno(3) - check and reset stream status
    fileno(3p) - map a stream pointer to a file descriptor
    fileno_unlocked(3) - nonlocking stdio functions
    filesystems(5) - Linux filesystem types: ext, ext2, ext3, ext4, hpfs, iso9660, JFS, minix, msdos, ncpfs nfs, ntfs, proc, Reiserfs, smb, sysv, umsdos, vfat, XFS, xiafs,
    filter(3x) - miscellaneous curses utility routines
    filter(7) - cups file conversion filter interface
    fincore(1) - count pages of file contents in core
    find-repos-of-install(1) - report which Yum repository a package was installed from
    find(1) - search for files in a directory hierarchy
    find(1p) - find files
    findfs(8) - find a filesystem by label or UUID
    find_key_by_type_and_name(3) - find a key by type and name
    findmnt(8) - find a filesystem
    find_pair(3x) - new curses color-pair functions
    fini_selinuxmnt(3) - initialize the global variable selinux_mnt
    finite(3) - BSD floating-point classification functions
    finitef(3) - BSD floating-point classification functions
    finitel(3) - BSD floating-point classification functions
    finit_module(2) - load a kernel module
    Firecfg(1) - Desktop integration utility for Firejail software.
    firecfg(1) - Desktop integration utility for Firejail software.
    firejail-login(5) - Login file syntax for Firejail
    firejail-profile(5) - Security profile file syntax for Firejail
    firejail-users(5) - Firejail user access database
    Firejail(1) - Linux namespaces sandbox program
    firejail(1) - Linux namespaces sandbox program
    firejail.users(5) - Firejail user access database
    Firemon(1) - Monitoring program for processes started in a Firejail sandbox.
    firemon(1) - Monitoring program for processes started in a Firejail sandbox.
    fixfiles(8) - fix file SELinux security contexts.
    flash(3x) - curses bell and screen flash routines
    __flbf(3) - interfaces to stdio FILE structure
    flistxattr(2) - list extended attribute names
    float.h(0p) - floating types
    flock(1) - manage locks from shell scripts
    flock(2) - apply or remove an advisory lock on an open file
    flockfile(3) - lock FILE for stdio
    flockfile(3p) - stdio locking functions
    floor(3) - largest integral value not greater than argument
    floor(3p) - floor function
    floorf(3) - largest integral value not greater than argument
    floorf(3p) - floor function
    floorl(3) - largest integral value not greater than argument
    floorl(3p) - floor function
    flow(8) - flow based traffic control filter
    flower(8) - flow based traffic control filter
    flowtop(8) - top-like netfilter TCP/UDP/SCTP/DCCP/ICMP(v6) flow tracking
    flushinp(3x) - miscellaneous curses utility routines
    _flushlbf(3) - interfaces to stdio FILE structure
    fma(3) - floating-point multiply and add
    fma(3p) - point multiply-add
    fmaf(3) - floating-point multiply and add
    fmaf(3p) - point multiply-add
    fmal(3) - floating-point multiply and add
    fmal(3p) - point multiply-add
    fmax(3) - determine maximum of two floating-point numbers
    fmax(3p) - point numbers
    fmaxf(3) - determine maximum of two floating-point numbers
    fmaxf(3p) - point numbers
    fmaxl(3) - determine maximum of two floating-point numbers
    fmaxl(3p) - point numbers
    fmemopen(3) - open memory as stream
    fmemopen(3p) - open a memory buffer stream
    fmin(3) - determine minimum of two floating-point numbers
    fmin(3p) - point numbers
    fminf(3) - determine minimum of two floating-point numbers
    fminf(3p) - point numbers
    fminl(3) - determine minimum of two floating-point numbers
    fminl(3p) - point numbers
    fmod(3) - floating-point remainder function
    fmod(3p) - point remainder value function
    fmodf(3) - floating-point remainder function
    fmodf(3p) - point remainder value function
    fmodl(3) - floating-point remainder function
    fmodl(3p) - point remainder value function
    fmt(1) - simple optimal text formatter
    fmtmsg(3) - print formatted error messages
    fmtmsg(3p) - display a message in the specified format on standard error and/or a system console
    fmtmsg.h(0p) - message display structures
    fnmatch(3) - match filename or pathname
    fnmatch(3p) - match a filename string or a pathname
    fnmatch.h(0p) - matching types
    fold(1) - wrap each input line to fit in specified width
    fold(1p) - filter for folding lines
    fopen(3) - stream open functions
    fopen(3p) - open a stream
    fopencookie(3) - opening a custom stream
    fork(2) - create a child process
    fork(3p) - create a new process
    forkpty(3) - terminal utility functions
    form(3x) - curses extension for programming forms
    form_cursor(3x) - position a form window cursor
    form_data(3x) - test for off-screen data in given forms
    form_driver(3x) - command-processing loop of the form system
    form_driver_w(3x) - command-processing loop of the form system
    form_field(3x) - make and break connections between fields and forms
    form_field_attributes(3x) - color and attribute control for form fields
    form_field_buffer(3x) - field buffer control
    form_field_info(3x) - retrieve field characteristics
    form_field_just(3x) - retrieve field characteristics
    form_field_new(3x) - create and destroy form fields
    form_field_opts(3x) - set and get field options
    form_fieldtype(3x) - define validation-field types
    form_field_userptr(3x) - associate application data with a form field
    form_field_validation(3x) - data type validation for fields
    form_hook(3x) - set hooks for automatic invocation by applications
    form_new(3x) - create and destroy forms
    form_new_page(3x) - form pagination functions
    form_opts(3x) - set and get form options
    form_opts_off(3x) - set and get form options
    form_opts_on(3x) - set and get form options
    form_page(3x) - set and get form page number
    form_post(3x) - write or erase forms from associated subwindows
    form_request_by_name(3x) - handle printable form request names
    form_requestname(3x) - handle printable form request names
    form_request_name(3x) - handle printable form request names
    form_userptr(3x) - associate application data with a form item
    form_variables(3x) - form system global variables
    form_win(3x) - make and break form window and subwindow associations
    fort77(1p) - FORTRAN compiler (FORTRAN)
    fpathconf(3) - get configuration values for files
    fpathconf(3p) - get configurable pathname variables
    fpclassify(3) - floating-point classification macros
    fpclassify(3p) - classify real floating type
    __fpending(3) - interfaces to stdio FILE structure
    fprintf(3) - formatted output conversion
    fprintf(3p) - print formatted output
    fpurge(3) - purge a stream
    __fpurge(3) - purge a stream
    fputc(3) - output of characters and strings
    fputc(3p) - put a byte on a stream
    fputc_unlocked(3) - nonlocking stdio functions
    fputs(3) - output of characters and strings
    fputs(3p) - put a string on a stream
    fputs_unlocked(3) - nonlocking stdio functions
    fputwc(3) - write a wide character to a FILE stream
    fputwc(3p) - character code on a stream
    fputwc_unlocked(3) - nonlocking stdio functions
    fputws(3) - write a wide-character string to a FILE stream
    fputws(3p) - character string on a stream
    fputws_unlocked(3) - nonlocking stdio functions
    FQ(8) - Fair Queue traffic policing
    fread(3) - binary stream input/output
    fread(3p) - binary input
    __freadable(3) - interfaces to stdio FILE structure
    __freading(3) - interfaces to stdio FILE structure
    fread_unlocked(3) - nonlocking stdio functions
    free(1) - Display amount of free and used memory in the system
    free(3) - allocate and free dynamic memory
    free(3p) - free allocated memory
    freeaddrinfo(3) - network address and service translation
    freeaddrinfo(3p) - get address information
    freecon(3) - get SELinux security context of a process
    freeconary(3) - get SELinux security context of a process
    free_field(3x) - create and destroy form fields
    free_form(3x) - create and destroy forms
    free_handle(3) - file handle operations
    __free_hook(3) - malloc debugging variables
    freehostent(3) - get network hostnames and addresses
    free_hugepages(2) - allocate or free huge pages
    freeifaddrs(3) - get interface addresses
    free_item(3x) - create and destroy menu items
    freelocale(3) - create, modify, and free a locale object
    freelocale(3p) - free resources allocated for a locale object
    free_menu(3x) - create and destroy menus
    free_pair(3x) - new curses color-pair functions
    fremovexattr(2) - remove an extended attribute
    freopen(3) - stream open functions
    freopen(3p) - open a stream
    frexp(3) - convert floating-point number to fractional and integral components
    frexp(3p) - extract mantissa and exponent from a double precision number
    frexpf(3) - convert floating-point number to fractional and integral components
    frexpf(3p) - extract mantissa and exponent from a double precision number
    frexpl(3) - convert floating-point number to fractional and integral components
    frexpl(3p) - extract mantissa and exponent from a double precision number
    fs(5) - Linux filesystem types: ext, ext2, ext3, ext4, hpfs, iso9660, JFS, minix, msdos, ncpfs nfs, ntfs, proc, Reiserfs, smb, sysv, umsdos, vfat, XFS, xiafs,
    fsadm(8) - utility to resize or check filesystem on a device
    fscanf(3) - input format conversion
    fscanf(3p) - convert formatted input
    fsck(8) - check and repair a Linux filesystem
    fsck.btrfs(8) - do nothing, successfully
    fsck.cramfs(8) - fsck compressed ROM file system
    fsck.minix(8) - check consistency of Minix filesystem
    fsck.xfs(8) - do nothing, successfully
    fseek(3) - reposition a stream
    fseek(3p) - position indicator in a stream
    fseeko(3) - seek to or report file position
    fseeko(3p) - position indicator in a stream
    fsetfilecon(3) - set SELinux security context of a file
    fsetfilecon_raw(3) - set SELinux security context of a file
    __fsetlocking(3) - interfaces to stdio FILE structure
    fsetpos(3) - reposition a stream
    fsetpos(3p) - set current file position
    fsetxattr(2) - set an extended attribute value
    fsfreeze(8) - suspend access to a filesystem (Ext3/4, ReiserFS, JFS, XFS)
    fssetdm_by_handle(3) - file handle operations
    fstab(5) - static information about the filesystems
    fstat(2) - get file status
    fstat(3p) - get file status
    fstat64(2) - get file status
    fstatat(2) - get file status
    fstatat(3p) - get file status
    fstatat64(2) - get file status
    fstatfs(2) - get filesystem statistics
    fstatfs64(2) - get filesystem statistics
    fstatvfs(2) - get filesystem statistics
    fstatvfs(3) - get filesystem statistics
    fstatvfs(3p) - get file system information
    fstrim(8) - discard unused blocks on a mounted filesystem
    fsync(2) - synchronize a file's in-core state with storage device
    fsync(3p) - synchronize changes to a file
    ftell(3) - reposition a stream
    ftell(3p) - return a file offset in a stream
    ftello(3) - seek to or report file position
    ftello(3p) - return a file offset in a stream
    ftime(3) - return date and time
    ftok(3) - convert a pathname and a project identifier to a System V IPC key
    ftok(3p) - generate an IPC key
    ftpusers(5) - list of users that may not log in via the FTP daemon
    ftruncate(2) - truncate a file to a specified length
    ftruncate(3p) - truncate a file to a specified length
    ftruncate64(2) - truncate a file to a specified length
    ftrylockfile(3) - lock FILE for stdio
    ftrylockfile(3p) - stdio locking functions
    fts(3) - traverse a file hierarchy
    fts_children(3) - traverse a file hierarchy
    fts_close(3) - traverse a file hierarchy
    fts_open(3) - traverse a file hierarchy
    fts_read(3) - traverse a file hierarchy
    fts_set(3) - traverse a file hierarchy
    ftw(3) - file tree walk
    ftw(3p) - traverse (walk) a file tree
    ftw.h(0p) - file tree traversal
    full(4) - always full device
    fullreport(8) - Display full report
    funlockfile(3) - lock FILE for stdio
    funlockfile(3p) - stdio locking functions
    fuse(4) - Filesystem in Userspace (FUSE) device
    fuse(8) - configuration and mount options for FUSE file systems
    fuse2fs(1) - FUSE file system client for ext2/ext3/ext4 file systems
    fuser(1) - identify processes using files or sockets
    fuser(1p) - list process IDs of all processes that have one or more files open
    fusermount3(1) - mount and unmount FUSE filesystems
    futex(2) - fast user-space locking
    futex(7) - fast user-space locking
    futimens(3) - change file timestamps with nanosecond precision
    futimens(3p) - set file access and modification times
    futimes(3) - change file timestamps
    futimesat(2) - change timestamps of a file relative to a directory file descriptor
    fw(8) - fwmark traffic control filter
    fwide(3) - set and determine the orientation of a FILE stream
    fwide(3p) - set stream orientation
    fwprintf(3) - formatted wide-character output conversion
    fwprintf(3p) - character output
    __fwritable(3) - interfaces to stdio FILE structure
    fwrite(3) - binary stream input/output
    fwrite(3p) - binary output
    fwrite_unlocked(3) - nonlocking stdio functions
    __fwriting(3) - interfaces to stdio FILE structure
    fwscanf(3p) - character input

top
    g++(1) - GNU project C and C++ compiler
    gai.conf(5) - getaddrinfo(3) configuration file
    gai_cancel(3) - asynchronous network address and service translation
    gai_error(3) - asynchronous network address and service translation
    gai_strerror(3) - network address and service translation
    gai_strerror(3p) - address and name information error description
    gai_suspend(3) - asynchronous network address and service translation
    galera_new_cluster(1) - starting a new Galera cluster
    galera_recovery(1) - recover from non-graceful shutdown
    gamma(3) - (logarithm of the) gamma function
    gammaf(3) - (logarithm of the) gamma function
    gammal(3) - (logarithm of the) gamma function
    ganglia2pcp(1) - import ganglia data and create a PCP archive
    gawk(1) - pattern scanning and processing language
    gcc(1) - GNU project C and C++ compiler
    gcore(1) - Generate a core file of a running program
    gcov-dump(1) - offline gcda and gcno profile dump tool
    gcov-tool(1) - offline gcda profile processing tool
    gcov(1) - coverage testing tool
    gcvt(3) - convert a floating-point number to a string
    gdb-add-index(1) - Add index files to speed up GDB
    gdb(1) - The GNU Debugger
    gdbinit(5) - GDB initialization scripts
    gdbserver(1) - Remote Server for the GNU Debugger
    gdiffmk(1) - mark differences between groff/nroff/troff files
    gencat(1p) - generate a formatted message catalog
    genhomedircon(8) - generate SELinux file context configuration entries for user home directories
    genl(8) - generic netlink utility frontend
    genpmda(1) - Performance Co-Pilot PMDA Generator
    genpolbools(8) - Rewrite a binary policy with different boolean settings
    genpolusers(8) - Generate new binary policy with updated user configuration
    get(1p) - get a version of an SCCS file (DEVELOPMENT)
    getaddrinfo(3) - network address and service translation
    getaddrinfo(3p) - get address information
    getaddrinfo_a(3) - asynchronous network address and service translation
    getaliasbyname(3) - read an alias entry
    getaliasbyname_r(3) - read an alias entry
    getaliasent(3) - read an alias entry
    getaliasent_r(3) - read an alias entry
    get_auditfail_action(3) - Get failure_action tunable value
    getauxval(3) - retrieve a value from the auxiliary vector
    get_avphys_pages(3) - get total and available physical page counts
    getbegyx(3x) - get curses cursor and window coordinates
    getbkgd(3x) - curses window background manipulation routines
    getbkgrnd(3x) - curses window complex background manipulation routines
    getc(3) - input of characters and strings
    getc(3p) - get a byte from a stream
    getcap(8) - examine file capabilities
    getcchar(3x) - Get a wide character string and rendition from a cchar_t or set a cchar_t from a wide-character string
    getch(3x) - get (or push back) characters from curses terminal keyboard
    getchar(3) - input of characters and strings
    getchar(3p) - get a byte from a stdin stream
    getchar_unlocked(3) - nonlocking stdio functions
    getchar_unlocked(3p) - stdio with explicit client locking
    getcon(3) - get SELinux security context of a process
    getconf(1p) - get configuration values
    getcon_raw(3) - get SELinux security context of a process
    getcontext(2) - get or set the user context
    getcontext(3) - get or set the user context
    getcpu(2) - determine CPU and NUMA node on which the calling thread is running
    getc_unlocked(3) - nonlocking stdio functions
    getc_unlocked(3p) - stdio with explicit client locking
    get_current_dir_name(3) - get current working directory
    getcwd(2) - get current working directory
    getcwd(3) - get current working directory
    getcwd(3p) - get the pathname of the current working directory
    getdate(3) - convert a date-plus-time string to broken-down time
    getdate(3p) - convert user format date and time
    getdate_err(3) - convert a date-plus-time string to broken-down time
    getdate_r(3) - convert a date-plus-time string to broken-down time
    get_default_context(3) - determine SELinux context(s) for user sessions
    get_default_context_with_level(3) - determine SELinux context(s) for user sessions
    get_default_context_with_role(3) - determine SELinux context(s) for user sessions
    get_default_context_with_rolelevel(3) - determine SELinux context(s) for user sessions
    get_default_role(3) - determine SELinux context(s) for user sessions
    get_default_type(3) - determine SELinux context(s) for user sessions
    getdelim(3) - delimited string input
    getdelim(3p) - read a delimited record from stream
    getdents(2) - get directory entries
    getdents64(2) - get directory entries
    getdirentries(3) - get directory entries in a filesystem-independent format
    getdomainname(2) - get/set NIS domain name
    getdtablesize(2) - get file descriptor table size
    getdtablesize(3) - get file descriptor table size
    getegid(2) - get group identity
    getegid(3p) - get the effective group ID
    getegid32(2) - get group identity
    getenforce(8) - get the current mode of SELinux
    getent(1) - get entries from Name Service Switch libraries
    getentropy(3) - fill a buffer with random bytes
    getenv(3) - get an environment variable
    getenv(3p) - get value of an environment variable
    geteuid(2) - get user identity
    geteuid(3p) - get the effective user ID
    geteuid32(2) - get user identity
    getexeccon(3) - get or set the SELinux security context used for executing a new process
    getexeccon_raw(3) - get or set the SELinux security context used for executing a new process
    getfacl(1) - get file access control lists
    getfattr(1) - get extended attributes of filesystem objects
    getfilecon(3) - get SELinux security context of a file
    getfilecon_raw(3) - get SELinux security context of a file
    getfscreatecon(3) - get or set the SELinux security context used for creating a new file system object
    getfscreatecon_raw(3) - get or set the SELinux security context used for creating a new file system object
    getfsent(3) - handle fstab entries
    getfsfile(3) - handle fstab entries
    getfsspec(3) - handle fstab entries
    getgid(2) - get group identity
    getgid(3p) - get the real group ID
    getgid32(2) - get group identity
    getgrent(3) - get group file entry
    getgrent(3p) - get the group database entry
    getgrent_r(3) - get group file entry reentrantly
    getgrgid(3) - get group file entry
    getgrgid(3p) - get group database entry for a group ID
    getgrgid_r(3) - get group file entry
    getgrgid_r(3p) - get group database entry for a group ID
    getgrnam(3) - get group file entry
    getgrnam(3p) - search group database for a name
    getgrnam_r(3) - get group file entry
    getgrnam_r(3p) - search group database for a name
    getgrouplist(3) - get list of groups to which a user belongs
    getgroups(2) - get/set list of supplementary group IDs
    getgroups(3p) - get supplementary group IDs
    getgroups32(2) - get/set list of supplementary group IDs
    gethostbyaddr(3) - get network host entry
    gethostbyaddr_r(3) - get network host entry
    gethostbyname(3) - get network host entry
    gethostbyname2(3) - get network host entry
    gethostbyname2_r(3) - get network host entry
    gethostbyname_r(3) - get network host entry
    gethostent(3) - get network host entry
    gethostent(3p) - network host database functions
    gethostent_r(3) - get network host entry
    gethostid(2) - get or set the unique identifier of the current host
    gethostid(3) - get or set the unique identifier of the current host
    gethostid(3p) - get an identifier for the current host
    gethostname(2) - get/set hostname
    gethostname(3p) - get name of current host
    getifaddrs(3) - get interface addresses
    getipnodebyaddr(3) - get network hostnames and addresses
    getipnodebyname(3) - get network hostnames and addresses
    getitimer(2) - get or set value of an interval timer
    getitimer(3p) - get and set value of interval timer
    get_kernel_syms(2) - retrieve exported kernel and module symbols
    getkeycodes(8) - print kernel scancode-to-keycode mapping table
    getkeycreatecon(3) - get or set the SELinux security context used for creating a new kernel keyrings
    getkeycreatecon_raw(3) - get or set the SELinux security context used for creating a new kernel keyrings
    getline(3) - delimited string input
    getline(3p) - read a delimited record from stream
    getloadavg(3) - get system load averages
    getlogin(3) - get username
    getlogin(3p) - get login name
    getlogin_r(3) - get username
    getlogin_r(3p) - get login name
    getmaxyx(3x) - get curses cursor and window coordinates
    get_mempolicy(2) - retrieve NUMA memory policy for a thread
    getmntent(3) - get filesystem descriptor file entry
    getmntent_r(3) - get filesystem descriptor file entry
    getmouse(3x) - mouse interface through curses
    getmsg(2) - unimplemented system calls
    getmsg(3p) - receive next message from a STREAMS file (STREAMS)
    get_myaddress(3) - library routines for remote procedure calls
    getnameinfo(3) - address-to-name translation in protocol-independent manner
    getnameinfo(3p) - get name information
    getnetbyaddr(3) - get network entry
    getnetbyaddr(3p) - network database functions
    getnetbyaddr_r(3) - get network entry (reentrant)
    getnetbyname(3) - get network entry
    getnetbyname(3p) - network database functions
    getnetbyname_r(3) - get network entry (reentrant)
    getnetent(3) - get network entry
    getnetent(3p) - network database functions
    getnetent_r(3) - get network entry (reentrant)
    getnetgrent(3) - handle network group entries
    getnetgrent_r(3) - handle network group entries
    get_nprocs(3) - get number of processors
    get_nprocs_conf(3) - get number of processors
    getnstr(3x) - accept character strings from curses terminal keyboard
    getn_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    getopt(1) - parse command options (enhanced)
    getopt(3) - Parse command-line options
    getopt(3p) - command option parsing
    getopt_long(3) - Parse command-line options
    getopt_long_only(3) - Parse command-line options
    getopts(1p) - parse utility options
    get_ordered_context_list(3) - determine SELinux context(s) for user sessions
    get_ordered_context_list_with_level(3) - determine SELinux context(s) for user sessions
    getpagesize(2) - get memory page size
    getparentpaths_by_handle(3) - file handle operations
    getparents_by_handle(3) - file handle operations
    getparyx(3x) - get curses cursor and window coordinates
    getpass(3) - get a password
    getpeercon(3) - get SELinux security context of a process
    getpeercon_raw(3) - get SELinux security context of a process
    getpeername(2) - get name of connected peer socket
    getpeername(3p) - get the name of the peer socket
    getpgid(2) - set/get process group
    getpgid(3p) - get the process group ID for a process
    getpgrp(2) - set/get process group
    getpgrp(3p) - get the process group ID of the calling process
    get_phys_pages(3) - get total and available physical page counts
    getpid(2) - get process identification
    getpid(3p) - get the process ID
    getpidcon(3) - get SELinux security context of a process
    getpidcon_raw(3) - get SELinux security context of a process
    getpmsg(2) - unimplemented system calls
    getpmsg(3p) - receive next message from a STREAMS file
    getppid(2) - get process identification
    getppid(3p) - get the parent process ID
    getprevcon(3) - get SELinux security context of a process
    getprevcon_raw(3) - get SELinux security context of a process
    getpriority(2) - get/set program scheduling priority
    getpriority(3p) - get and set the nice value
    getprotent(3p) - network protocol database functions
    getprotobyname(3) - get protocol entry
    getprotobyname(3p) - network protocol database functions
    getprotobyname_r(3) - get protocol entry (reentrant)
    getprotobynumber(3) - get protocol entry
    getprotobynumber(3p) - network protocol database functions
    getprotobynumber_r(3) - get protocol entry (reentrant)
    getprotoent(3) - get protocol entry
    getprotoent(3p) - network protocol database functions
    getprotoent_r(3) - get protocol entry (reentrant)
    getpt(3) - open the pseudoterminal master (PTM)
    getpw(3) - reconstruct password line entry
    getpwent(3) - get password file entry
    getpwent(3p) - get user database entry
    getpwent_r(3) - get passwd file entry reentrantly
    getpwnam(3) - get password file entry
    getpwnam(3p) - search user database for a name
    getpwnam_r(3) - get password file entry
    getpwnam_r(3p) - search user database for a name
    getpwuid(3) - get password file entry
    getpwuid(3p) - search user database for a user ID
    getpwuid_r(3) - get password file entry
    getpwuid_r(3p) - search user database for a user ID
    getrandom(2) - obtain a series of random bytes
    getresgid(2) - get real, effective and saved user/group IDs
    getresgid32(2) - get real, effective and saved user/group IDs
    getresuid(2) - get real, effective and saved user/group IDs
    getresuid32(2) - get real, effective and saved user/group IDs
    getrlimit(2) - get/set resource limits
    getrlimit(3p) - control maximum resource consumption
    get_robust_list(2) - get/set list of robust futexes
    getrpcbyname(3) - get RPC entry
    getrpcbyname_r(3) - get RPC entry (reentrant)
    getrpcbynumber(3) - get RPC entry
    getrpcbynumber_r(3) - get RPC entry (reentrant)
    getrpcent(3) - get RPC entry
    getrpcent_r(3) - get RPC entry (reentrant)
    getrpcport(3) - get RPC port number
    getrusage(2) - get resource usage
    getrusage(3p) - get information about resource utilization
    gets(3) - get a string from standard input (DEPRECATED)
    gets(3p) - get a string from a stdin stream
    getsebool(8) - get SELinux boolean value(s)
    getservbyname(3) - get service entry
    getservbyname(3p) - network services database functions
    getservbyname_r(3) - get service entry (reentrant)
    getservbyport(3) - get service entry
    getservbyport(3p) - network services database functions
    getservbyport_r(3) - get service entry (reentrant)
    getservent(3) - get service entry
    getservent(3p) - network services database functions
    getservent_r(3) - get service entry (reentrant)
    getseuserbyname(3) - get SELinux username and level for a given Linux username
    getsid(2) - get session ID
    getsid(3p) - get the process group ID of a session leader
    getsockcreatecon(3) - get or set the SELinux security context used for creating a new labeled sockets
    getsockcreatecon_raw(3) - get or set the SELinux security context used for creating a new labeled sockets
    getsockname(2) - get socket name
    getsockname(3p) - get the socket name
    getsockopt(2) - get and set options on sockets
    getsockopt(3p) - get the socket options
    getspent(3) - get shadow password file entry
    getspent_r(3) - get shadow password file entry
    getspnam(3) - get shadow password file entry
    getspnam_r(3) - get shadow password file entry
    getstr(3x) - accept character strings from curses terminal keyboard
    getsubopt(3) - parse suboption arguments from a string
    getsubopt(3p) - parse suboption arguments from a string
    getsyx(3x) - low-level curses routines
    gettext(1) - translate message
    gettext(3) - translate message
    gettextize(1) - install or upgrade gettext infrastructure
    get_thread_area(2) - set a GDT entry for thread-local storage
    gettid(2) - get thread identification
    gettimeofday(2) - get / set time
    gettimeofday(3p) - get the date and time
    getttyent(3) - get ttys file entry
    getttynam(3) - get ttys file entry
    getuid(2) - get user identity
    getuid(3p) - get a real user ID
    getuid32(2) - get user identity
    getumask(3) - get file creation mask
    getunwind(2) - copy the unwind data to caller's buffer
    getusershell(3) - get permitted user shells
    getutent(3) - access utmp file entries
    getutent_r(3) - access utmp file entries
    getutid(3) - access utmp file entries
    getutid_r(3) - access utmp file entries
    getutline(3) - access utmp file entries
    getutline_r(3) - access utmp file entries
    getutmp(3) - copy utmp structure to utmpx, and vice versa
    getutmpx(3) - copy utmp structure to utmpx, and vice versa
    getutxent(3) - access utmp file entries
    getutxent(3p) - get user accounting database entries
    getutxid(3) - access utmp file entries
    getutxid(3p) - user accounting database functions
    getutxline(3) - access utmp file entries
    getutxline(3p) - user accounting database functions
    getw(3) - input and output of words (ints)
    getwc(3) - read a wide character from a FILE stream
    getwc(3p) - get a wide character from a stream
    get_wch(3x) - get (or push back) a wide character from curses terminal keyboard
    getwchar(3) - read a wide character from standard input
    getwchar(3p) - get a wide character from a stdin stream
    getwchar_unlocked(3) - nonlocking stdio functions
    getwc_unlocked(3) - nonlocking stdio functions
    getwd(3) - get current working directory
    getwin(3x) - miscellaneous curses utility routines
    get_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    getxattr(2) - retrieve an extended attribute value
    getyx(3x) - get curses cursor and window coordinates
    gfortran(1) - GNU Fortran compiler
    git-add(1) - Add file contents to the index
    git-am(1) - Apply a series of patches from a mailbox
    git-annotate(1) - Annotate file lines with commit information
    git-apply(1) - Apply a patch to files and/or to the index
    git-archimport(1) - Import a GNU Arch repository into Git
    git-archive(1) - Create an archive of files from a named tree
    git-bisect(1) - Use binary search to find the commit that introduced a bug
    git-blame(1) - Show what revision and author last modified each line of a file
    git-branch(1) - List, create, or delete branches
    git-bundle(1) - Move objects and refs by archive
    git-cat-file(1) - Provide content or type and size information for repository objects
    git-check-attr(1) - Display gitattributes information
    git-check-ignore(1) - Debug gitignore / exclude files
    git-check-mailmap(1) - Show canonical names and email addresses of contacts
    git-check-ref-format(1) - Ensures that a reference name is well formed
    git-checkout-index(1) - Copy files from the index to the working tree
    git-checkout(1) - Switch branches or restore working tree files
    git-cherry-pick(1) - Apply the changes introduced by some existing commits
    git-cherry(1) - Find commits yet to be applied to upstream
    git-citool(1) - Graphical alternative to git-commit
    git-clean(1) - Remove untracked files from the working tree
    git-clone(1) - Clone a repository into a new directory
    git-column(1) - Display data in columns
    git-commit-graph(1) - Write and verify Git commit-graph files
    git-commit-tree(1) - Create a new commit object
    git-commit(1) - Record changes to the repository
    git-config(1) - Get and set repository or global options
    git-count-objects(1) - Count unpacked number of objects and their disk consumption
    git-credential-cache--daemon(1) - Temporarily store user credentials in memory
    git-credential-cache(1) - Helper to temporarily store passwords in memory
    git-credential-store(1) - Helper to store credentials on disk
    git-credential(1) - Retrieve and store user credentials
    git-cvsexportcommit(1) - Export a single commit to a CVS checkout
    git-cvsimport(1) - Salvage your data out of another SCM people love to hate
    git-cvsserver(1) - A CVS server emulator for Git
    git-daemon(1) - A really simple server for Git repositories
    git-describe(1) - Give an object a human readable name based on an available ref
    git-diff-files(1) - Compares files in the working tree and the index
    git-diff-index(1) - Compare a tree to the working tree or index
    git-diff-tree(1) - Compares the content and mode of blobs found via two tree objects
    git-diff(1) - Show changes between commits, commit and working tree, etc
    git-difftool(1) - Show changes using common diff tools
    git-fast-export(1) - Git data exporter
    git-fast-import(1) - Backend for fast Git data importers
    git-fetch-pack(1) - Receive missing objects from another repository
    git-fetch(1) - Download objects and refs from another repository
    git-filter-branch(1) - Rewrite branches
    git-fmt-merge-msg(1) - Produce a merge commit message
    git-for-each-ref(1) - Output information on each ref
    git-format-patch(1) - Prepare patches for e-mail submission
    git-fsck-objects(1) - Verifies the connectivity and validity of the objects in the database
    git-fsck(1) - Verifies the connectivity and validity of the objects in the database
    git-gc(1) - Cleanup unnecessary files and optimize the local repository
    git-get-tar-commit-id(1) - Extract commit ID from an archive created using git-archive
    git-grep(1) - Print lines matching a pattern
    git-gui(1) - A portable graphical interface to Git
    git-hash-object(1) - Compute object ID and optionally creates a blob from a file
    git-help(1) - Display help information about Git
    git-http-backend(1) - Server side implementation of Git over HTTP
    git-http-fetch(1) - Download from a remote Git repository via HTTP
    git-http-push(1) - Push objects over HTTP/DAV to another repository
    git-imap-send(1) - Send a collection of patches from stdin to an IMAP folder
    git-index-pack(1) - Build pack index file for an existing packed archive
    git-init-db(1) - Creates an empty Git repository
    git-init(1) - Create an empty Git repository or reinitialize an existing one
    git-instaweb(1) - Instantly browse your working repository in gitweb
    git-interpret-trailers(1) - add or parse structured information in commit messages
    git-log(1) - Show commit logs
    git-ls-files(1) - Show information about files in the index and the working tree
    git-ls-remote(1) - List references in a remote repository
    git-ls-tree(1) - List the contents of a tree object
    git-mailinfo(1) - Extracts patch and authorship from a single e-mail message
    git-mailsplit(1) - Simple UNIX mbox splitter program
    git-merge-base(1) - Find as good common ancestors as possible for a merge
    git-merge-file(1) - Run a three-way file merge
    git-merge-index(1) - Run a merge for files needing merging
    git-merge-one-file(1) - The standard helper program to use with git-merge-index
    git-merge-tree(1) - Show three-way merge without touching index
    git-merge(1) - Join two or more development histories together
    git-mergetool--lib(1) - Common Git merge tool shell scriptlets
    git-mergetool(1) - Run merge conflict resolution tools to resolve merge conflicts
    git-mktag(1) - Creates a tag object
    git-mktree(1) - Build a tree-object from ls-tree formatted text
    git-multi-pack-index(1) - Write and verify multi-pack-indexes
    git-mv(1) - Move or rename a file, a directory, or a symlink
    git-name-rev(1) - Find symbolic names for given revs
    git-notes(1) - Add or inspect object notes
    git-p4(1) - Import from and submit to Perforce repositories
    git-pack-objects(1) - Create a packed archive of objects
    git-pack-redundant(1) - Find redundant pack files
    git-pack-refs(1) - Pack heads and tags for efficient repository access
    git-parse-remote(1) - Routines to help parsing remote repository access parameters
    git-patch-id(1) - Compute unique ID for a patch
    git-prune-packed(1) - Remove extra objects that are already in pack files
    git-prune(1) - Prune all unreachable objects from the object database
    git-pull(1) - Fetch from and integrate with another repository or a local branch
    git-push(1) - Update remote refs along with associated objects
    git-quiltimport(1) - Applies a quilt patchset onto the current branch
    git-range-diff(1) - Compare two commit ranges (e.g. two versions of a branch)
    git-read-tree(1) - Reads tree information into the index
    git-rebase(1) - Reapply commits on top of another base tip
    git-receive-pack(1) - Receive what is pushed into the repository
    git-reflog(1) - Manage reflog information
    git-relink(1) - Hardlink common objects in local repositories
    git-remote-ext(1) - Bridge smart transport to external command.
    git-remote-fd(1) - Reflect smart transport stream back to caller
    git-remote-testgit(1) - Example remote-helper
    git-remote(1) - Manage set of tracked repositories
    git-repack(1) - Pack unpacked objects in a repository
    git-replace(1) - Create, list, delete refs to replace objects
    git-request-pull(1) - Generates a summary of pending changes
    git-rerere(1) - Reuse recorded resolution of conflicted merges
    git-reset(1) - Reset current HEAD to the specified state
    git-rev-list(1) - Lists commit objects in reverse chronological order
    git-rev-parse(1) - Pick out and massage parameters
    git-revert(1) - Revert some existing commits
    git-rm(1) - Remove files from the working tree and from the index
    git-send-email(1) - Send a collection of patches as emails
    git-send-pack(1) - Push objects over Git protocol to another repository
    git-series(1) - track changes to a patch series with git
    git-sh-i18n--envsubst(1) - Git's own envsubst(1) for i18n fallbacks
    git-sh-i18n(1) - Git's i18n setup code for shell scripts
    git-sh-setup(1) - Common Git shell script setup code
    git-shell(1) - Restricted login shell for Git-only SSH access
    git-shortlog(1) - Summarize 'git log' output
    git-show-branch(1) - Show branches and their commits
    git-show-index(1) - Show packed archive index
    git-show-ref(1) - List references in a local repository
    git-show(1) - Show various types of objects
    git-stage(1) - Add file contents to the staging area
    git-stash(1) - Stash the changes in a dirty working directory away
    git-status(1) - Show the working tree status
    git-stripspace(1) - Remove unnecessary whitespace
    git-submodule(1) - Initialize, update or inspect submodules
    git-svn(1) - Bidirectional operation between a Subversion repository and Git
    git-symbolic-ref(1) - Read, modify and delete symbolic refs
    git-tag(1) - Create, list, delete or verify a tag object signed with GPG
    git-unpack-file(1) - Creates a temporary file with a blob's contents
    git-unpack-objects(1) - Unpack objects from a packed archive
    git-update-index(1) - Register file contents in the working tree to the index
    git-update-ref(1) - Update the object name stored in a ref safely
    git-update-server-info(1) - Update auxiliary info file to help dumb servers
    git-upload-archive(1) - Send archive back to git-archive
    git-upload-pack(1) - Send objects packed back to git-fetch-pack
    git-var(1) - Show a Git logical variable
    git-verify-commit(1) - Check the GPG signature of commits
    git-verify-pack(1) - Validate packed Git archive files
    git-verify-tag(1) - Check the GPG signature of tags
    git-web--browse(1) - Git helper script to launch a web browser
    git-whatchanged(1) - Show logs with difference each commit introduces
    git-worktree(1) - Manage multiple working trees
    git-write-tree(1) - Create a tree object from the current index
    git(1) - the stupid content tracker
    gitattributes(5) - Defining attributes per path
    gitcli(7) - Git command-line interface and conventions
    gitcore-tutorial(7) - A Git core tutorial for developers
    gitcredentials(7) - providing usernames and passwords to Git
    gitcvs-migration(7) - Git for CVS users
    gitdiffcore(7) - Tweaking diff output
    giteveryday(7) - A useful minimum set of commands for Everyday Git
    gitglossary(7) - A Git Glossary
    githooks(5) - Hooks used by Git
    gitignore(5) - Specifies intentionally untracked files to ignore
    gitk(1) - The Git repository browser
    gitmodules(5) - Defining submodule properties
    gitnamespaces(7) - Git namespaces
    gitremote-helpers(1) - Helper programs to interact with remote repositories
    gitrepository-layout(5) - Git Repository Layout
    gitrevisions(7) - Specifying revisions and ranges for Git
    gitsubmodules(7) - mounting one repository inside another
    gittutorial-2(7) - A tutorial introduction to Git: part two
    gittutorial(7) - A tutorial introduction to Git
    gitweb(1) - Git web interface (web frontend to Git repositories)
    gitweb.conf(5) - Gitweb (Git web interface) configuration file
    gitworkflows(7) - An overview of recommended workflows with Git
    glibc(7) - overview of standard C libraries on Linux
    glilypond(1) - integrate lilypond parts into groff
    glob(3) - find pathnames matching a pattern, free memory from glob()
    glob(3p) - generate pathnames matching a pattern
    glob(7) - globbing pathnames
    glob.h(0p) - matching types
    globfree(3) - find pathnames matching a pattern, free memory from glob()
    globfree(3p) - generate pathnames matching a pattern
    gmtime(3) - transform date and time to broken-down time or ASCII
    gmtime(3p) - down UTC time
    gmtime_r(3) - transform date and time to broken-down time or ASCII
    gmtime_r(3p) - down UTC time
    GNU(1) - compare two files byte by byte
    gnu_dev_major(3) - manage a device number
    gnu_dev_makedev(3) - manage a device number
    gnu_dev_minor(3) - manage a device number
    gnu_get_libc_release(3) - get glibc version and release
    gnu_get_libc_version(3) - get glibc version and release
    gnutls-cli-debug(1) - GnuTLS debug client
    gnutls-cli(1) - GnuTLS client
    gnutls-serv(1) - GnuTLS server
    gnutls_aead_cipher_decrypt(3) - API function
    gnutls_aead_cipher_deinit(3) - API function
    gnutls_aead_cipher_encrypt(3) - API function
    gnutls_aead_cipher_encryptv(3) - API function
    gnutls_aead_cipher_init(3) - API function
    gnutls_alert_get(3) - API function
    gnutls_alert_get_name(3) - API function
    gnutls_alert_get_strname(3) - API function
    gnutls_alert_send(3) - API function
    gnutls_alert_send_appropriate(3) - API function
    gnutls_alpn_get_selected_protocol(3) - API function
    gnutls_alpn_set_protocols(3) - API function
    gnutls_anon_allocate_client_credentials(3) - API function
    gnutls_anon_allocate_server_credentials(3) - API function
    gnutls_anon_free_client_credentials(3) - API function
    gnutls_anon_free_server_credentials(3) - API function
    gnutls_anon_set_params_function(3) - API function
    gnutls_anon_set_server_dh_params(3) - API function
    gnutls_anon_set_server_known_dh_params(3) - API function
    gnutls_anon_set_server_params_function(3) - API function
    gnutls_auth_client_get_type(3) - API function
    gnutls_auth_get_type(3) - API function
    gnutls_auth_server_get_type(3) - API function
    gnutls_base64_decode2(3) - API function
    gnutls_base64_encode2(3) - API function
    gnutls_buffer_append_data(3) - API function
    gnutls_bye(3) - API function
    gnutls_certificate_activation_time_peers(3) - API function
    gnutls_certificate_allocate_credentials(3) - API function
    gnutls_certificate_client_get_request_status(3) - API function
    gnutls_certificate_expiration_time_peers(3) - API function
    gnutls_certificate_free_ca_names(3) - API function
    gnutls_certificate_free_cas(3) - API function
    gnutls_certificate_free_credentials(3) - API function
    gnutls_certificate_free_crls(3) - API function
    gnutls_certificate_free_keys(3) - API function
    gnutls_certificate_get_crt_raw(3) - API function
    gnutls_certificate_get_issuer(3) - API function
    gnutls_certificate_get_ocsp_expiration(3) - API function
    gnutls_certificate_get_ours(3) - API function
    gnutls_certificate_get_peers(3) - API function
    gnutls_certificate_get_peers_subkey_id(3) - API function
    gnutls_certificate_get_trust_list(3) - API function
    gnutls_certificate_get_verify_flags(3) - API function
    gnutls_certificate_get_x509_crt(3) - API function
    gnutls_certificate_get_x509_key(3) - API function
    gnutls_certificate_send_x509_rdn_sequence(3) - API function
    gnutls_certificate_server_set_request(3) - API function
    gnutls_certificate_set_dh_params(3) - API function
    gnutls_certificate_set_flags(3) - API function
    gnutls_certificate_set_key(3) - API function
    gnutls_certificate_set_known_dh_params(3) - API function
    gnutls_certificate_set_ocsp_status_request_file(3) - API function
    gnutls_certificate_set_ocsp_status_request_file2(3) - API function
    gnutls_certificate_set_ocsp_status_request_function(3) - API function
    gnutls_certificate_set_ocsp_status_request_function2(3) - API function
    gnutls_certificate_set_ocsp_status_request_mem(3) - API function
    gnutls_certificate_set_params_function(3) - API function
    gnutls_certificate_set_pin_function(3) - API function
    gnutls_certificate_set_retrieve_function(3) - API function
    gnutls_certificate_set_retrieve_function2(3) - API function
    gnutls_certificate_set_retrieve_function3(3) - API function
    gnutls_certificate_set_trust_list(3) - API function
    gnutls_certificate_set_verify_flags(3) - API function
    gnutls_certificate_set_verify_function(3) - API function
    gnutls_certificate_set_verify_limits(3) - API function
    gnutls_certificate_set_x509_crl(3) - API function
    gnutls_certificate_set_x509_crl_file(3) - API function
    gnutls_certificate_set_x509_crl_mem(3) - API function
    gnutls_certificate_set_x509_key(3) - API function
    gnutls_certificate_set_x509_key_file(3) - API function
    gnutls_certificate_set_x509_key_file2(3) - API function
    gnutls_certificate_set_x509_key_mem(3) - API function
    gnutls_certificate_set_x509_key_mem2(3) - API function
    gnutls_certificate_set_x509_simple_pkcs12_file(3) - API function
    gnutls_certificate_set_x509_simple_pkcs12_mem(3) - API function
    gnutls_certificate_set_x509_system_trust(3) - API function
    gnutls_certificate_set_x509_trust(3) - API function
    gnutls_certificate_set_x509_trust_dir(3) - API function
    gnutls_certificate_set_x509_trust_file(3) - API function
    gnutls_certificate_set_x509_trust_mem(3) - API function
    gnutls_certificate_type_get(3) - API function
    gnutls_certificate_type_get2(3) - API function
    gnutls_certificate_type_get_id(3) - API function
    gnutls_certificate_type_get_name(3) - API function
    gnutls_certificate_type_list(3) - API function
    gnutls_certificate_verification_status_print(3) - API function
    gnutls_certificate_verify_peers(3) - API function
    gnutls_certificate_verify_peers2(3) - API function
    gnutls_certificate_verify_peers3(3) - API function
    gnutls_check_version(3) - API function
    gnutls_cipher_add_auth(3) - API function
    gnutls_cipher_decrypt(3) - API function
    gnutls_cipher_decrypt2(3) - API function
    gnutls_cipher_deinit(3) - API function
    gnutls_cipher_encrypt(3) - API function
    gnutls_cipher_encrypt2(3) - API function
    gnutls_cipher_get(3) - API function
    gnutls_cipher_get_block_size(3) - API function
    gnutls_cipher_get_id(3) - API function
    gnutls_cipher_get_iv_size(3) - API function
    gnutls_cipher_get_key_size(3) - API function
    gnutls_cipher_get_name(3) - API function
    gnutls_cipher_get_tag_size(3) - API function
    gnutls_cipher_init(3) - API function
    gnutls_cipher_list(3) - API function
    gnutls_cipher_set_iv(3) - API function
    gnutls_cipher_suite_get_name(3) - API function
    gnutls_cipher_suite_info(3) - API function
    gnutls_cipher_tag(3) - API function
    gnutls_compression_get(3) - API function
    gnutls_compression_get_id(3) - API function
    gnutls_compression_get_name(3) - API function
    gnutls_compression_list(3) - API function
    gnutls_credentials_clear(3) - API function
    gnutls_credentials_get(3) - API function
    gnutls_credentials_set(3) - API function
    gnutls_crypto_register_aead_cipher(3) - API function
    gnutls_crypto_register_cipher(3) - API function
    gnutls_crypto_register_digest(3) - API function
    gnutls_crypto_register_mac(3) - API function
    gnutls_db_check_entry(3) - API function
    gnutls_db_check_entry_time(3) - API function
    gnutls_db_get_default_cache_expiration(3) - API function
    gnutls_db_get_ptr(3) - API function
    gnutls_db_remove_session(3) - API function
    gnutls_db_set_cache_expiration(3) - API function
    gnutls_db_set_ptr(3) - API function
    gnutls_db_set_remove_function(3) - API function
    gnutls_db_set_retrieve_function(3) - API function
    gnutls_db_set_store_function(3) - API function
    gnutls_decode_ber_digest_info(3) - API function
    gnutls_decode_gost_rs_value(3) - API function
    gnutls_decode_rs_value(3) - API function
    gnutls_deinit(3) - API function
    gnutls_dh_get_group(3) - API function
    gnutls_dh_get_peers_public_bits(3) - API function
    gnutls_dh_get_prime_bits(3) - API function
    gnutls_dh_get_pubkey(3) - API function
    gnutls_dh_get_secret_bits(3) - API function
    gnutls_dh_params_cpy(3) - API function
    gnutls_dh_params_deinit(3) - API function
    gnutls_dh_params_export2_pkcs3(3) - API function
    gnutls_dh_params_export_pkcs3(3) - API function
    gnutls_dh_params_export_raw(3) - API function
    gnutls_dh_params_generate2(3) - API function
    gnutls_dh_params_import_dsa(3) - API function
    gnutls_dh_params_import_pkcs3(3) - API function
    gnutls_dh_params_import_raw(3) - API function
    gnutls_dh_params_import_raw2(3) - API function
    gnutls_dh_params_init(3) - API function
    gnutls_dh_set_prime_bits(3) - API function
    gnutls_digest_get_id(3) - API function
    gnutls_digest_get_name(3) - API function
    gnutls_digest_get_oid(3) - API function
    gnutls_digest_list(3) - API function
    gnutls_dtls_cookie_send(3) - API function
    gnutls_dtls_cookie_verify(3) - API function
    gnutls_dtls_get_data_mtu(3) - API function
    gnutls_dtls_get_mtu(3) - API function
    gnutls_dtls_get_timeout(3) - API function
    gnutls_dtls_prestate_set(3) - API function
    gnutls_dtls_set_data_mtu(3) - API function
    gnutls_dtls_set_mtu(3) - API function
    gnutls_dtls_set_timeouts(3) - API function
    gnutls_ecc_curve_get(3) - API function
    gnutls_ecc_curve_get_id(3) - API function
    gnutls_ecc_curve_get_name(3) - API function
    gnutls_ecc_curve_get_oid(3) - API function
    gnutls_ecc_curve_get_pk(3) - API function
    gnutls_ecc_curve_get_size(3) - API function
    gnutls_ecc_curve_list(3) - API function
    gnutls_encode_ber_digest_info(3) - API function
    gnutls_encode_gost_rs_value(3) - API function
    gnutls_encode_rs_value(3) - API function
    gnutls_error_is_fatal(3) - API function
    gnutls_error_to_alert(3) - API function
    gnutls_est_record_overhead_size(3) - API function
    gnutls_ext_get_current_msg(3) - API function
    gnutls_ext_get_data(3) - API function
    gnutls_ext_get_name(3) - API function
    gnutls_ext_raw_parse(3) - API function
    gnutls_ext_register(3) - API function
    gnutls_ext_set_data(3) - API function
    gnutls_fingerprint(3) - API function
    gnutls_fips140_mode_enabled(3) - API function
    gnutls_fips140_set_mode(3) - API function
    gnutls_global_deinit(3) - API function
    gnutls_global_init(3) - API function
    gnutls_global_set_audit_log_function(3) - API function
    gnutls_global_set_log_function(3) - API function
    gnutls_global_set_log_level(3) - API function
    gnutls_global_set_mem_functions(3) - API function
    gnutls_global_set_mutex(3) - API function
    gnutls_global_set_time_function(3) - API function
    gnutls_gost_paramset_get_name(3) - API function
    gnutls_gost_paramset_get_oid(3) - API function
    gnutls_group_get(3) - API function
    gnutls_group_get_id(3) - API function
    gnutls_group_get_name(3) - API function
    gnutls_group_list(3) - API function
    gnutls_handshake(3) - API function
    gnutls_handshake_description_get_name(3) - API function
    gnutls_handshake_get_last_in(3) - API function
    gnutls_handshake_get_last_out(3) - API function
    gnutls_handshake_set_hook_function(3) - API function
    gnutls_handshake_set_max_packet_length(3) - API function
    gnutls_handshake_set_post_client_hello_function(3) - API function
    gnutls_handshake_set_private_extensions(3) - API function
    gnutls_handshake_set_random(3) - API function
    gnutls_handshake_set_timeout(3) - API function
    gnutls_hash(3) - API function
    gnutls_hash_deinit(3) - API function
    gnutls_hash_fast(3) - API function
    gnutls_hash_get_len(3) - API function
    gnutls_hash_init(3) - API function
    gnutls_hash_output(3) - API function
    gnutls_heartbeat_allowed(3) - API function
    gnutls_heartbeat_enable(3) - API function
    gnutls_heartbeat_get_timeout(3) - API function
    gnutls_heartbeat_ping(3) - API function
    gnutls_heartbeat_pong(3) - API function
    gnutls_heartbeat_set_timeouts(3) - API function
    gnutls_hex2bin(3) - API function
    gnutls_hex_decode(3) - API function
    gnutls_hex_decode2(3) - API function
    gnutls_hex_encode(3) - API function
    gnutls_hex_encode2(3) - API function
    gnutls_hmac(3) - API function
    gnutls_hmac_deinit(3) - API function
    gnutls_hmac_fast(3) - API function
    gnutls_hmac_get_len(3) - API function
    gnutls_hmac_init(3) - API function
    gnutls_hmac_output(3) - API function
    gnutls_hmac_set_nonce(3) - API function
    gnutls_idna_map(3) - API function
    gnutls_idna_reverse_map(3) - API function
    gnutls_init(3) - API function
    gnutls_key_generate(3) - API function
    gnutls_kx_get(3) - API function
    gnutls_kx_get_id(3) - API function
    gnutls_kx_get_name(3) - API function
    gnutls_kx_list(3) - API function
    gnutls_load_file(3) - API function
    gnutls_mac_get(3) - API function
    gnutls_mac_get_id(3) - API function
    gnutls_mac_get_key_size(3) - API function
    gnutls_mac_get_name(3) - API function
    gnutls_mac_get_nonce_size(3) - API function
    gnutls_mac_list(3) - API function
    gnutls_memcmp(3) - API function
    gnutls_memset(3) - API function
    gnutls_ocsp_req_add_cert(3) - API function
    gnutls_ocsp_req_add_cert_id(3) - API function
    gnutls_ocsp_req_deinit(3) - API function
    gnutls_ocsp_req_export(3) - API function
    gnutls_ocsp_req_get_cert_id(3) - API function
    gnutls_ocsp_req_get_extension(3) - API function
    gnutls_ocsp_req_get_nonce(3) - API function
    gnutls_ocsp_req_get_version(3) - API function
    gnutls_ocsp_req_import(3) - API function
    gnutls_ocsp_req_init(3) - API function
    gnutls_ocsp_req_print(3) - API function
    gnutls_ocsp_req_randomize_nonce(3) - API function
    gnutls_ocsp_req_set_extension(3) - API function
    gnutls_ocsp_req_set_nonce(3) - API function
    gnutls_ocsp_resp_check_crt(3) - API function
    gnutls_ocsp_resp_deinit(3) - API function
    gnutls_ocsp_resp_export(3) - API function
    gnutls_ocsp_resp_export2(3) - API function
    gnutls_ocsp_resp_get_certs(3) - API function
    gnutls_ocsp_resp_get_extension(3) - API function
    gnutls_ocsp_resp_get_nonce(3) - API function
    gnutls_ocsp_resp_get_produced(3) - API function
    gnutls_ocsp_resp_get_responder(3) - API function
    gnutls_ocsp_resp_get_responder2(3) - API function
    gnutls_ocsp_resp_get_responder_raw_id(3) - API function
    gnutls_ocsp_resp_get_response(3) - API function
    gnutls_ocsp_resp_get_signature(3) - API function
    gnutls_ocsp_resp_get_signature_algorithm(3) - API function
    gnutls_ocsp_resp_get_single(3) - API function
    gnutls_ocsp_resp_get_status(3) - API function
    gnutls_ocsp_resp_get_version(3) - API function
    gnutls_ocsp_resp_import(3) - API function
    gnutls_ocsp_resp_import2(3) - API function
    gnutls_ocsp_resp_init(3) - API function
    gnutls_ocsp_resp_list_import2(3) - API function
    gnutls_ocsp_resp_print(3) - API function
    gnutls_ocsp_resp_verify(3) - API function
    gnutls_ocsp_resp_verify_direct(3) - API function
    gnutls_ocsp_status_request_enable_client(3) - API function
    gnutls_ocsp_status_request_get(3) - API function
    gnutls_ocsp_status_request_get2(3) - API function
    gnutls_ocsp_status_request_is_checked(3) - API function
    gnutls_oid_to_digest(3) - API function
    gnutls_oid_to_ecc_curve(3) - API function
    gnutls_oid_to_gost_paramset(3) - API function
    gnutls_oid_to_mac(3) - API function
    gnutls_oid_to_pk(3) - API function
    gnutls_oid_to_sign(3) - API function
    gnutls_openpgp_privkey_sign_hash(3) - API function
    gnutls_openpgp_send_cert(3) - API function
    gnutls_packet_deinit(3) - API function
    gnutls_packet_get(3) - API function
    gnutls_pcert_deinit(3) - API function
    gnutls_pcert_export_openpgp(3) - API function
    gnutls_pcert_export_x509(3) - API function
    gnutls_pcert_import_openpgp(3) - API function
    gnutls_pcert_import_openpgp_raw(3) - API function
    gnutls_pcert_import_x509(3) - API function
    gnutls_pcert_import_x509_list(3) - API function
    gnutls_pcert_import_x509_raw(3) - API function
    gnutls_pcert_list_import_x509_file(3) - API function
    gnutls_pcert_list_import_x509_raw(3) - API function
    gnutls_pem_base64_decode(3) - API function
    gnutls_pem_base64_decode2(3) - API function
    gnutls_pem_base64_encode(3) - API function
    gnutls_pem_base64_encode2(3) - API function
    gnutls_perror(3) - API function
    gnutls_pk_algorithm_get_name(3) - API function
    gnutls_pk_bits_to_sec_param(3) - API function
    gnutls_pkcs11_add_provider(3) - API function
    gnutls_pkcs11_copy_attached_extension(3) - API function
    gnutls_pkcs11_copy_pubkey(3) - API function
    gnutls_pkcs11_copy_secret_key(3) - API function
    gnutls_pkcs11_copy_x509_crt(3) - API function
    gnutls_pkcs11_copy_x509_crt2(3) - API function
    gnutls_pkcs11_copy_x509_privkey(3) - API function
    gnutls_pkcs11_copy_x509_privkey2(3) - API function
    gnutls_pkcs11_crt_is_known(3) - API function
    gnutls_pkcs11_deinit(3) - API function
    gnutls_pkcs11_delete_url(3) - API function
    gnutls_pkcs11_get_pin_function(3) - API function
    gnutls_pkcs11_get_raw_issuer(3) - API function
    gnutls_pkcs11_get_raw_issuer_by_dn(3) - API function
    gnutls_pkcs11_get_raw_issuer_by_subject_key_id(3) - API function
    gnutls_pkcs11_init(3) - API function
    gnutls_pkcs11_obj_deinit(3) - API function
    gnutls_pkcs11_obj_export(3) - API function
    gnutls_pkcs11_obj_export2(3) - API function
    gnutls_pkcs11_obj_export3(3) - API function
    gnutls_pkcs11_obj_export_url(3) - API function
    gnutls_pkcs11_obj_flags_get_str(3) - API function
    gnutls_pkcs11_obj_get_exts(3) - API function
    gnutls_pkcs11_obj_get_flags(3) - API function
    gnutls_pkcs11_obj_get_info(3) - API function
    gnutls_pkcs11_obj_get_ptr(3) - API function
    gnutls_pkcs11_obj_get_type(3) - API function
    gnutls_pkcs11_obj_import_url(3) - API function
    gnutls_pkcs11_obj_init(3) - API function
    gnutls_pkcs11_obj_list_import_url3(3) - API function
    gnutls_pkcs11_obj_list_import_url4(3) - API function
    gnutls_pkcs11_obj_set_info(3) - API function
    gnutls_pkcs11_obj_set_pin_function(3) - API function
    gnutls_pkcs11_privkey_cpy(3) - API function
    gnutls_pkcs11_privkey_deinit(3) - API function
    gnutls_pkcs11_privkey_export_pubkey(3) - API function
    gnutls_pkcs11_privkey_export_url(3) - API function
    gnutls_pkcs11_privkey_generate(3) - API function
    gnutls_pkcs11_privkey_generate2(3) - API function
    gnutls_pkcs11_privkey_generate3(3) - API function
    gnutls_pkcs11_privkey_get_info(3) - API function
    gnutls_pkcs11_privkey_get_pk_algorithm(3) - API function
    gnutls_pkcs11_privkey_import_url(3) - API function
    gnutls_pkcs11_privkey_init(3) - API function
    gnutls_pkcs11_privkey_set_pin_function(3) - API function
    gnutls_pkcs11_privkey_status(3) - API function
    gnutls_pkcs11_reinit(3) - API function
    gnutls_pkcs11_set_pin_function(3) - API function
    gnutls_pkcs11_set_token_function(3) - API function
    gnutls_pkcs11_token_check_mechanism(3) - API function
    gnutls_pkcs11_token_get_flags(3) - API function
    gnutls_pkcs11_token_get_info(3) - API function
    gnutls_pkcs11_token_get_mechanism(3) - API function
    gnutls_pkcs11_token_get_ptr(3) - API function
    gnutls_pkcs11_token_get_random(3) - API function
    gnutls_pkcs11_token_get_url(3) - API function
    gnutls_pkcs11_token_init(3) - API function
    gnutls_pkcs11_token_set_pin(3) - API function
    gnutls_pkcs11_type_get_name(3) - API function
    gnutls_pkcs12_bag_decrypt(3) - API function
    gnutls_pkcs12_bag_deinit(3) - API function
    gnutls_pkcs12_bag_enc_info(3) - API function
    gnutls_pkcs12_bag_encrypt(3) - API function
    gnutls_pkcs12_bag_get_count(3) - API function
    gnutls_pkcs12_bag_get_data(3) - API function
    gnutls_pkcs12_bag_get_friendly_name(3) - API function
    gnutls_pkcs12_bag_get_key_id(3) - API function
    gnutls_pkcs12_bag_get_type(3) - API function
    gnutls_pkcs12_bag_init(3) - API function
    gnutls_pkcs12_bag_set_crl(3) - API function
    gnutls_pkcs12_bag_set_crt(3) - API function
    gnutls_pkcs12_bag_set_data(3) - API function
    gnutls_pkcs12_bag_set_friendly_name(3) - API function
    gnutls_pkcs12_bag_set_key_id(3) - API function
    gnutls_pkcs12_bag_set_privkey(3) - API function
    gnutls_pkcs12_deinit(3) - API function
    gnutls_pkcs12_export(3) - API function
    gnutls_pkcs12_export2(3) - API function
    gnutls_pkcs12_generate_mac(3) - API function
    gnutls_pkcs12_generate_mac2(3) - API function
    gnutls_pkcs12_get_bag(3) - API function
    gnutls_pkcs12_import(3) - API function
    gnutls_pkcs12_init(3) - API function
    gnutls_pkcs12_mac_info(3) - API function
    gnutls_pkcs12_set_bag(3) - API function
    gnutls_pkcs12_simple_parse(3) - API function
    gnutls_pkcs12_verify_mac(3) - API function
    gnutls_pkcs7_add_attr(3) - API function
    gnutls_pkcs7_attrs_deinit(3) - API function
    gnutls_pkcs7_deinit(3) - API function
    gnutls_pkcs7_delete_crl(3) - API function
    gnutls_pkcs7_delete_crt(3) - API function
    gnutls_pkcs7_export(3) - API function
    gnutls_pkcs7_export2(3) - API function
    gnutls_pkcs7_get_attr(3) - API function
    gnutls_pkcs7_get_crl_count(3) - API function
    gnutls_pkcs7_get_crl_raw(3) - API function
    gnutls_pkcs7_get_crl_raw2(3) - API function
    gnutls_pkcs7_get_crt_count(3) - API function
    gnutls_pkcs7_get_crt_raw(3) - API function
    gnutls_pkcs7_get_crt_raw2(3) - API function
    gnutls_pkcs7_get_embedded_data(3) - API function
    gnutls_pkcs7_get_embedded_data_oid(3) - API function
    gnutls_pkcs7_get_signature_count(3) - API function
    gnutls_pkcs7_get_signature_info(3) - API function
    gnutls_pkcs7_import(3) - API function
    gnutls_pkcs7_init(3) - API function
    gnutls_pkcs7_print(3) - API function
    gnutls_pkcs7_set_crl(3) - API function
    gnutls_pkcs7_set_crl_raw(3) - API function
    gnutls_pkcs7_set_crt(3) - API function
    gnutls_pkcs7_set_crt_raw(3) - API function
    gnutls_pkcs7_sign(3) - API function
    gnutls_pkcs7_signature_info_deinit(3) - API function
    gnutls_pkcs7_verify(3) - API function
    gnutls_pkcs7_verify_direct(3) - API function
    gnutls_pkcs8_info(3) - API function
    gnutls_pkcs_schema_get_name(3) - API function
    gnutls_pkcs_schema_get_oid(3) - API function
    gnutls_pk_get_id(3) - API function
    gnutls_pk_get_name(3) - API function
    gnutls_pk_get_oid(3) - API function
    gnutls_pk_list(3) - API function
    gnutls_pk_to_sign(3) - API function
    gnutls_prf(3) - API function
    gnutls_prf_raw(3) - API function
    gnutls_prf_rfc5705(3) - API function
    gnutls_priority_certificate_type_list(3) - API function
    gnutls_priority_certificate_type_list2(3) - API function
    gnutls_priority_cipher_list(3) - API function
    gnutls_priority_compression_list(3) - API function
    gnutls_priority_deinit(3) - API function
    gnutls_priority_ecc_curve_list(3) - API function
    gnutls_priority_get_cipher_suite_index(3) - API function
    gnutls_priority_group_list(3) - API function
    gnutls_priority_init(3) - API function
    gnutls_priority_init2(3) - API function
    gnutls_priority_kx_list(3) - API function
    gnutls_priority_mac_list(3) - API function
    gnutls_priority_protocol_list(3) - API function
    gnutls_priority_set(3) - API function
    gnutls_priority_set_direct(3) - API function
    gnutls_priority_sign_list(3) - API function
    gnutls_priority_string_list(3) - API function
    gnutls_privkey_decrypt_data(3) - API function
    gnutls_privkey_deinit(3) - API function
    gnutls_privkey_export_dsa_raw(3) - API function
    gnutls_privkey_export_dsa_raw2(3) - API function
    gnutls_privkey_export_ecc_raw(3) - API function
    gnutls_privkey_export_ecc_raw2(3) - API function
    gnutls_privkey_export_gost_raw2(3) - API function
    gnutls_privkey_export_openpgp(3) - API function
    gnutls_privkey_export_pkcs11(3) - API function
    gnutls_privkey_export_rsa_raw(3) - API function
    gnutls_privkey_export_rsa_raw2(3) - API function
    gnutls_privkey_export_x509(3) - API function
    gnutls_privkey_generate(3) - API function
    gnutls_privkey_generate2(3) - API function
    gnutls_privkey_get_pk_algorithm(3) - API function
    gnutls_privkey_get_seed(3) - API function
    gnutls_privkey_get_spki(3) - API function
    gnutls_privkey_get_type(3) - API function
    gnutls_privkey_import_dsa_raw(3) - API function
    gnutls_privkey_import_ecc_raw(3) - API function
    gnutls_privkey_import_ext(3) - API function
    gnutls_privkey_import_ext2(3) - API function
    gnutls_privkey_import_ext3(3) - API function
    gnutls_privkey_import_ext4(3) - API function
    gnutls_privkey_import_gost_raw(3) - API function
    gnutls_privkey_import_openpgp(3) - API function
    gnutls_privkey_import_openpgp_raw(3) - API function
    gnutls_privkey_import_pkcs11(3) - API function
    gnutls_privkey_import_pkcs11_url(3) - API function
    gnutls_privkey_import_rsa_raw(3) - API function
    gnutls_privkey_import_tpm_raw(3) - API function
    gnutls_privkey_import_tpm_url(3) - API function
    gnutls_privkey_import_url(3) - API function
    gnutls_privkey_import_x509(3) - API function
    gnutls_privkey_import_x509_raw(3) - API function
    gnutls_privkey_init(3) - API function
    gnutls_privkey_set_flags(3) - API function
    gnutls_privkey_set_pin_function(3) - API function
    gnutls_privkey_set_spki(3) - API function
    gnutls_privkey_sign_data(3) - API function
    gnutls_privkey_sign_data2(3) - API function
    gnutls_privkey_sign_hash(3) - API function
    gnutls_privkey_sign_hash2(3) - API function
    gnutls_privkey_status(3) - API function
    gnutls_privkey_verify_params(3) - API function
    gnutls_privkey_verify_seed(3) - API function
    gnutls_protocol_get_id(3) - API function
    gnutls_protocol_get_name(3) - API function
    gnutls_protocol_get_version(3) - API function
    gnutls_protocol_list(3) - API function
    gnutls_psk_allocate_client_credentials(3) - API function
    gnutls_psk_allocate_server_credentials(3) - API function
    gnutls_psk_client_get_hint(3) - API function
    gnutls_psk_free_client_credentials(3) - API function
    gnutls_psk_free_server_credentials(3) - API function
    gnutls_psk_server_get_username(3) - API function
    gnutls_psk_set_client_credentials(3) - API function
    gnutls_psk_set_client_credentials_function(3) - API function
    gnutls_psk_set_params_function(3) - API function
    gnutls_psk_set_server_credentials_file(3) - API function
    gnutls_psk_set_server_credentials_function(3) - API function
    gnutls_psk_set_server_credentials_hint(3) - API function
    gnutls_psk_set_server_dh_params(3) - API function
    gnutls_psk_set_server_known_dh_params(3) - API function
    gnutls_psk_set_server_params_function(3) - API function
    gnutls_pubkey_deinit(3) - API function
    gnutls_pubkey_encrypt_data(3) - API function
    gnutls_pubkey_export(3) - API function
    gnutls_pubkey_export2(3) - API function
    gnutls_pubkey_export_dsa_raw(3) - API function
    gnutls_pubkey_export_dsa_raw2(3) - API function
    gnutls_pubkey_export_ecc_raw(3) - API function
    gnutls_pubkey_export_ecc_raw2(3) - API function
    gnutls_pubkey_export_ecc_x962(3) - API function
    gnutls_pubkey_export_gost_raw2(3) - API function
    gnutls_pubkey_export_rsa_raw(3) - API function
    gnutls_pubkey_export_rsa_raw2(3) - API function
    gnutls_pubkey_get_key_id(3) - API function
    gnutls_pubkey_get_key_usage(3) - API function
    gnutls_pubkey_get_openpgp_key_id(3) - API function
    gnutls_pubkey_get_pk_algorithm(3) - API function
    gnutls_pubkey_get_preferred_hash_algorithm(3) - API function
    gnutls_pubkey_get_spki(3) - API function
    gnutls_pubkey_import(3) - API function
    gnutls_pubkey_import_dsa_raw(3) - API function
    gnutls_pubkey_import_ecc_raw(3) - API function
    gnutls_pubkey_import_ecc_x962(3) - API function
    gnutls_pubkey_import_gost_raw(3) - API function
    gnutls_pubkey_import_openpgp(3) - API function
    gnutls_pubkey_import_openpgp_raw(3) - API function
    gnutls_pubkey_import_pkcs11(3) - API function
    gnutls_pubkey_import_privkey(3) - API function
    gnutls_pubkey_import_rsa_raw(3) - API function
    gnutls_pubkey_import_tpm_raw(3) - API function
    gnutls_pubkey_import_tpm_url(3) - API function
    gnutls_pubkey_import_url(3) - API function
    gnutls_pubkey_import_x509(3) - API function
    gnutls_pubkey_import_x509_crq(3) - API function
    gnutls_pubkey_import_x509_raw(3) - API function
    gnutls_pubkey_init(3) - API function
    gnutls_pubkey_print(3) - API function
    gnutls_pubkey_set_key_usage(3) - API function
    gnutls_pubkey_set_pin_function(3) - API function
    gnutls_pubkey_set_spki(3) - API function
    gnutls_pubkey_verify_data2(3) - API function
    gnutls_pubkey_verify_hash2(3) - API function
    gnutls_pubkey_verify_params(3) - API function
    gnutls_random_art(3) - API function
    gnutls_range_split(3) - API function
    gnutls_reauth(3) - API function
    gnutls_record_can_use_length_hiding(3) - API function
    gnutls_record_check_corked(3) - API function
    gnutls_record_check_pending(3) - API function
    gnutls_record_cork(3) - API function
    gnutls_record_disable_padding(3) - API function
    gnutls_record_discard_queued(3) - API function
    gnutls_record_get_direction(3) - API function
    gnutls_record_get_discarded(3) - API function
    gnutls_record_get_max_size(3) - API function
    gnutls_record_get_state(3) - API function
    gnutls_record_overhead_size(3) - API function
    gnutls_record_recv(3) - API function
    gnutls_record_recv_packet(3) - API function
    gnutls_record_recv_seq(3) - API function
    gnutls_record_send(3) - API function
    gnutls_record_send2(3) - API function
    gnutls_record_send_range(3) - API function
    gnutls_record_set_max_early_data_size(3) - API function
    gnutls_record_set_max_size(3) - API function
    gnutls_record_set_state(3) - API function
    gnutls_record_set_timeout(3) - API function
    gnutls_record_uncork(3) - API function
    gnutls_register_custom_url(3) - API function
    gnutls_rehandshake(3) - API function
    gnutls_rnd(3) - API function
    gnutls_rnd_refresh(3) - API function
    gnutls_safe_renegotiation_status(3) - API function
    gnutls_sec_param_get_name(3) - API function
    gnutls_sec_param_to_pk_bits(3) - API function
    gnutls_sec_param_to_symmetric_bits(3) - API function
    gnutls_server_name_get(3) - API function
    gnutls_server_name_set(3) - API function
    gnutls_session_channel_binding(3) - API function
    gnutls_session_enable_compatibility_mode(3) - API function
    gnutls_session_etm_status(3) - API function
    gnutls_session_ext_master_secret_status(3) - API function
    gnutls_session_ext_register(3) - API function
    gnutls_session_force_valid(3) - API function
    gnutls_session_get_data(3) - API function
    gnutls_session_get_data2(3) - API function
    gnutls_session_get_desc(3) - API function
    gnutls_session_get_flags(3) - API function
    gnutls_session_get_id(3) - API function
    gnutls_session_get_id2(3) - API function
    gnutls_session_get_master_secret(3) - API function
    gnutls_session_get_ptr(3) - API function
    gnutls_session_get_random(3) - API function
    gnutls_session_get_verify_cert_status(3) - API function
    gnutls_session_is_resumed(3) - API function
    gnutls_session_key_update(3) - API function
    gnutls_session_resumption_requested(3) - API function
    gnutls_session_set_data(3) - API function
    gnutls_session_set_id(3) - API function
    gnutls_session_set_premaster(3) - API function
    gnutls_session_set_ptr(3) - API function
    gnutls_session_set_verify_cert(3) - API function
    gnutls_session_set_verify_cert2(3) - API function
    gnutls_session_set_verify_function(3) - API function
    gnutls_session_supplemental_register(3) - API function
    gnutls_session_ticket_enable_client(3) - API function
    gnutls_session_ticket_enable_server(3) - API function
    gnutls_session_ticket_key_generate(3) - API function
    gnutls_session_ticket_send(3) - API function
    gnutls_set_default_priority(3) - API function
    gnutls_set_default_priority_append(3) - API function
    gnutls_sign_algorithm_get(3) - API function
    gnutls_sign_algorithm_get_client(3) - API function
    gnutls_sign_algorithm_get_requested(3) - API function
    gnutls_sign_get_hash_algorithm(3) - API function
    gnutls_sign_get_id(3) - API function
    gnutls_sign_get_name(3) - API function
    gnutls_sign_get_oid(3) - API function
    gnutls_sign_get_pk_algorithm(3) - API function
    gnutls_sign_is_secure(3) - API function
    gnutls_sign_is_secure2(3) - API function
    gnutls_sign_list(3) - API function
    gnutls_sign_supports_pk_algorithm(3) - API function
    gnutls_srp_allocate_client_credentials(3) - API function
    gnutls_srp_allocate_server_credentials(3) - API function
    gnutls_srp_base64_decode(3) - API function
    gnutls_srp_base64_decode2(3) - API function
    gnutls_srp_base64_encode(3) - API function
    gnutls_srp_base64_encode2(3) - API function
    gnutls_srp_free_client_credentials(3) - API function
    gnutls_srp_free_server_credentials(3) - API function
    gnutls_srp_server_get_username(3) - API function
    gnutls_srp_set_client_credentials(3) - API function
    gnutls_srp_set_client_credentials_function(3) - API function
    gnutls_srp_set_prime_bits(3) - API function
    gnutls_srp_set_server_credentials_file(3) - API function
    gnutls_srp_set_server_credentials_function(3) - API function
    gnutls_srp_set_server_fake_salt_seed(3) - API function
    gnutls_srp_verifier(3) - API function
    gnutls_srtp_get_keys(3) - API function
    gnutls_srtp_get_mki(3) - API function
    gnutls_srtp_get_profile_id(3) - API function
    gnutls_srtp_get_profile_name(3) - API function
    gnutls_srtp_get_selected_profile(3) - API function
    gnutls_srtp_set_mki(3) - API function
    gnutls_srtp_set_profile(3) - API function
    gnutls_srtp_set_profile_direct(3) - API function
    gnutls_store_commitment(3) - API function
    gnutls_store_pubkey(3) - API function
    gnutls_strerror(3) - API function
    gnutls_strerror_name(3) - API function
    gnutls_subject_alt_names_deinit(3) - API function
    gnutls_subject_alt_names_get(3) - API function
    gnutls_subject_alt_names_init(3) - API function
    gnutls_subject_alt_names_set(3) - API function
    gnutls_supplemental_get_name(3) - API function
    gnutls_supplemental_recv(3) - API function
    gnutls_supplemental_register(3) - API function
    gnutls_supplemental_send(3) - API function
    gnutls_system_key_add_x509(3) - API function
    gnutls_system_key_delete(3) - API function
    gnutls_system_key_iter_deinit(3) - API function
    gnutls_system_key_iter_get_info(3) - API function
    gnutls_system_recv_timeout(3) - API function
    gnutls_tdb_deinit(3) - API function
    gnutls_tdb_init(3) - API function
    gnutls_tdb_set_store_commitment_func(3) - API function
    gnutls_tdb_set_store_func(3) - API function
    gnutls_tdb_set_verify_func(3) - API function
    gnutls_tpm_get_registered(3) - API function
    gnutls_tpm_key_list_deinit(3) - API function
    gnutls_tpm_key_list_get_url(3) - API function
    gnutls_tpm_privkey_delete(3) - API function
    gnutls_tpm_privkey_generate(3) - API function
    gnutls_transport_get_int(3) - API function
    gnutls_transport_get_int2(3) - API function
    gnutls_transport_get_ptr(3) - API function
    gnutls_transport_get_ptr2(3) - API function
    gnutls_transport_set_errno(3) - API function
    gnutls_transport_set_errno_function(3) - API function
    gnutls_transport_set_fastopen(3) - API function
    gnutls_transport_set_int(3) - API function
    gnutls_transport_set_int2(3) - API function
    gnutls_transport_set_ptr(3) - API function
    gnutls_transport_set_ptr2(3) - API function
    gnutls_transport_set_pull_function(3) - API function
    gnutls_transport_set_pull_timeout_function(3) - API function
    gnutls_transport_set_push_function(3) - API function
    gnutls_transport_set_vec_push_function(3) - API function
    gnutls_url_is_supported(3) - API function
    gnutls_utf8_password_normalize(3) - API function
    gnutls_verify_stored_pubkey(3) - API function
    gnutls_x509_aia_deinit(3) - API function
    gnutls_x509_aia_get(3) - API function
    gnutls_x509_aia_init(3) - API function
    gnutls_x509_aia_set(3) - API function
    gnutls_x509_aki_deinit(3) - API function
    gnutls_x509_aki_get_cert_issuer(3) - API function
    gnutls_x509_aki_get_id(3) - API function
    gnutls_x509_aki_init(3) - API function
    gnutls_x509_aki_set_cert_issuer(3) - API function
    gnutls_x509_aki_set_id(3) - API function
    gnutls_x509_cidr_to_rfc5280(3) - API function
    gnutls_x509_crl_check_issuer(3) - API function
    gnutls_x509_crl_deinit(3) - API function
    gnutls_x509_crl_dist_points_deinit(3) - API function
    gnutls_x509_crl_dist_points_get(3) - API function
    gnutls_x509_crl_dist_points_init(3) - API function
    gnutls_x509_crl_dist_points_set(3) - API function
    gnutls_x509_crl_export(3) - API function
    gnutls_x509_crl_export2(3) - API function
    gnutls_x509_crl_get_authority_key_gn_serial(3) - API function
    gnutls_x509_crl_get_authority_key_id(3) - API function
    gnutls_x509_crl_get_crt_count(3) - API function
    gnutls_x509_crl_get_crt_serial(3) - API function
    gnutls_x509_crl_get_dn_oid(3) - API function
    gnutls_x509_crl_get_extension_data(3) - API function
    gnutls_x509_crl_get_extension_data2(3) - API function
    gnutls_x509_crl_get_extension_info(3) - API function
    gnutls_x509_crl_get_extension_oid(3) - API function
    gnutls_x509_crl_get_issuer_dn(3) - API function
    gnutls_x509_crl_get_issuer_dn2(3) - API function
    gnutls_x509_crl_get_issuer_dn3(3) - API function
    gnutls_x509_crl_get_issuer_dn_by_oid(3) - API function
    gnutls_x509_crl_get_next_update(3) - API function
    gnutls_x509_crl_get_number(3) - API function
    gnutls_x509_crl_get_raw_issuer_dn(3) - API function
    gnutls_x509_crl_get_signature(3) - API function
    gnutls_x509_crl_get_signature_algorithm(3) - API function
    gnutls_x509_crl_get_signature_oid(3) - API function
    gnutls_x509_crl_get_this_update(3) - API function
    gnutls_x509_crl_get_version(3) - API function
    gnutls_x509_crl_import(3) - API function
    gnutls_x509_crl_init(3) - API function
    gnutls_x509_crl_iter_crt_serial(3) - API function
    gnutls_x509_crl_iter_deinit(3) - API function
    gnutls_x509_crl_list_import(3) - API function
    gnutls_x509_crl_list_import2(3) - API function
    gnutls_x509_crl_print(3) - API function
    gnutls_x509_crl_privkey_sign(3) - API function
    gnutls_x509_crl_set_authority_key_id(3) - API function
    gnutls_x509_crl_set_crt(3) - API function
    gnutls_x509_crl_set_crt_serial(3) - API function
    gnutls_x509_crl_set_next_update(3) - API function
    gnutls_x509_crl_set_number(3) - API function
    gnutls_x509_crl_set_this_update(3) - API function
    gnutls_x509_crl_set_version(3) - API function
    gnutls_x509_crl_sign(3) - API function
    gnutls_x509_crl_sign2(3) - API function
    gnutls_x509_crl_verify(3) - API function
    gnutls_x509_crq_deinit(3) - API function
    gnutls_x509_crq_export(3) - API function
    gnutls_x509_crq_export2(3) - API function
    gnutls_x509_crq_get_attribute_by_oid(3) - API function
    gnutls_x509_crq_get_attribute_data(3) - API function
    gnutls_x509_crq_get_attribute_info(3) - API function
    gnutls_x509_crq_get_basic_constraints(3) - API function
    gnutls_x509_crq_get_challenge_password(3) - API function
    gnutls_x509_crq_get_dn(3) - API function
    gnutls_x509_crq_get_dn2(3) - API function
    gnutls_x509_crq_get_dn3(3) - API function
    gnutls_x509_crq_get_dn_by_oid(3) - API function
    gnutls_x509_crq_get_dn_oid(3) - API function
    gnutls_x509_crq_get_extension_by_oid(3) - API function
    gnutls_x509_crq_get_extension_by_oid2(3) - API function
    gnutls_x509_crq_get_extension_data(3) - API function
    gnutls_x509_crq_get_extension_data2(3) - API function
    gnutls_x509_crq_get_extension_info(3) - API function
    gnutls_x509_crq_get_key_id(3) - API function
    gnutls_x509_crq_get_key_purpose_oid(3) - API function
    gnutls_x509_crq_get_key_rsa_raw(3) - API function
    gnutls_x509_crq_get_key_usage(3) - API function
    gnutls_x509_crq_get_pk_algorithm(3) - API function
    gnutls_x509_crq_get_pk_oid(3) - API function
    gnutls_x509_crq_get_private_key_usage_period(3) - API function
    gnutls_x509_crq_get_signature_algorithm(3) - API function
    gnutls_x509_crq_get_signature_oid(3) - API function
    gnutls_x509_crq_get_spki(3) - API function
    gnutls_x509_crq_get_subject_alt_name(3) - API function
    gnutls_x509_crq_get_subject_alt_othername_oid(3) - API function
    gnutls_x509_crq_get_tlsfeatures(3) - API function
    gnutls_x509_crq_get_version(3) - API function
    gnutls_x509_crq_import(3) - API function
    gnutls_x509_crq_init(3) - API function
    gnutls_x509_crq_print(3) - API function
    gnutls_x509_crq_privkey_sign(3) - API function
    gnutls_x509_crq_set_attribute_by_oid(3) - API function
    gnutls_x509_crq_set_basic_constraints(3) - API function
    gnutls_x509_crq_set_challenge_password(3) - API function
    gnutls_x509_crq_set_dn(3) - API function
    gnutls_x509_crq_set_dn_by_oid(3) - API function
    gnutls_x509_crq_set_extension_by_oid(3) - API function
    gnutls_x509_crq_set_key(3) - API function
    gnutls_x509_crq_set_key_purpose_oid(3) - API function
    gnutls_x509_crq_set_key_rsa_raw(3) - API function
    gnutls_x509_crq_set_key_usage(3) - API function
    gnutls_x509_crq_set_private_key_usage_period(3) - API function
    gnutls_x509_crq_set_pubkey(3) - API function
    gnutls_x509_crq_set_spki(3) - API function
    gnutls_x509_crq_set_subject_alt_name(3) - API function
    gnutls_x509_crq_set_subject_alt_othername(3) - API function
    gnutls_x509_crq_set_tlsfeatures(3) - API function
    gnutls_x509_crq_set_version(3) - API function
    gnutls_x509_crq_sign(3) - API function
    gnutls_x509_crq_sign2(3) - API function
    gnutls_x509_crq_verify(3) - API function
    gnutls_x509_crt_check_email(3) - API function
    gnutls_x509_crt_check_hostname(3) - API function
    gnutls_x509_crt_check_hostname2(3) - API function
    gnutls_x509_crt_check_ip(3) - API function
    gnutls_x509_crt_check_issuer(3) - API function
    gnutls_x509_crt_check_key_purpose(3) - API function
    gnutls_x509_crt_check_revocation(3) - API function
    gnutls_x509_crt_cpy_crl_dist_points(3) - API function
    gnutls_x509_crt_deinit(3) - API function
    gnutls_x509_crt_equals(3) - This function compares two gnutls_x509_crt_t certificates
    gnutls_x509_crt_equals2(3) - This function compares a gnutls_x509_crt_t cert with DER data
    gnutls_x509_crt_export(3) - API function
    gnutls_x509_crt_export2(3) - API function
    gnutls_x509_crt_get_activation_time(3) - API function
    gnutls_x509_crt_get_authority_info_access(3) - API function
    gnutls_x509_crt_get_authority_key_gn_serial(3) - API function
    gnutls_x509_crt_get_authority_key_id(3) - API function
    gnutls_x509_crt_get_basic_constraints(3) - API function
    gnutls_x509_crt_get_ca_status(3) - API function
    gnutls_x509_crt_get_crl_dist_points(3) - API function
    gnutls_x509_crt_get_dn(3) - API function
    gnutls_x509_crt_get_dn2(3) - API function
    gnutls_x509_crt_get_dn3(3) - API function
    gnutls_x509_crt_get_dn_by_oid(3) - API function
    gnutls_x509_crt_get_dn_oid(3) - API function
    gnutls_x509_crt_get_expiration_time(3) - API function
    gnutls_x509_crt_get_extension_by_oid(3) - API function
    gnutls_x509_crt_get_extension_by_oid2(3) - API function
    gnutls_x509_crt_get_extension_data(3) - API function
    gnutls_x509_crt_get_extension_data2(3) - API function
    gnutls_x509_crt_get_extension_info(3) - API function
    gnutls_x509_crt_get_extension_oid(3) - API function
    gnutls_x509_crt_get_fingerprint(3) - API function
    gnutls_x509_crt_get_inhibit_anypolicy(3) - API function
    gnutls_x509_crt_get_issuer(3) - API function
    gnutls_x509_crt_get_issuer_alt_name(3) - API function
    gnutls_x509_crt_get_issuer_alt_name2(3) - API function
    gnutls_x509_crt_get_issuer_alt_othername_oid(3) - API function
    gnutls_x509_crt_get_issuer_dn(3) - API function
    gnutls_x509_crt_get_issuer_dn2(3) - API function
    gnutls_x509_crt_get_issuer_dn3(3) - API function
    gnutls_x509_crt_get_issuer_dn_by_oid(3) - API function
    gnutls_x509_crt_get_issuer_dn_oid(3) - API function
    gnutls_x509_crt_get_issuer_unique_id(3) - API function
    gnutls_x509_crt_get_key_id(3) - API function
    gnutls_x509_crt_get_key_purpose_oid(3) - API function
    gnutls_x509_crt_get_key_usage(3) - API function
    gnutls_x509_crt_get_name_constraints(3) - API function
    gnutls_x509_crt_get_pk_algorithm(3) - API function
    gnutls_x509_crt_get_pk_dsa_raw(3) - API function
    gnutls_x509_crt_get_pk_ecc_raw(3) - API function
    gnutls_x509_crt_get_pk_gost_raw(3) - API function
    gnutls_x509_crt_get_pk_oid(3) - API function
    gnutls_x509_crt_get_pk_rsa_raw(3) - API function
    gnutls_x509_crt_get_policy(3) - API function
    gnutls_x509_crt_get_preferred_hash_algorithm(3) - API function
    gnutls_x509_crt_get_private_key_usage_period(3) - API function
    gnutls_x509_crt_get_proxy(3) - API function
    gnutls_x509_crt_get_raw_dn(3) - API function
    gnutls_x509_crt_get_raw_issuer_dn(3) - API function
    gnutls_x509_crt_get_serial(3) - API function
    gnutls_x509_crt_get_signature(3) - API function
    gnutls_x509_crt_get_signature_algorithm(3) - API function
    gnutls_x509_crt_get_signature_oid(3) - API function
    gnutls_x509_crt_get_spki(3) - API function
    gnutls_x509_crt_get_subject(3) - API function
    gnutls_x509_crt_get_subject_alt_name(3) - API function
    gnutls_x509_crt_get_subject_alt_name2(3) - API function
    gnutls_x509_crt_get_subject_alt_othername_oid(3) - API function
    gnutls_x509_crt_get_subject_key_id(3) - API function
    gnutls_x509_crt_get_subject_unique_id(3) - API function
    gnutls_x509_crt_get_tlsfeatures(3) - API function
    gnutls_x509_crt_get_version(3) - API function
    gnutls_x509_crt_import(3) - API function
    gnutls_x509_crt_import_pkcs11(3) - API function
    gnutls_x509_crt_import_url(3) - API function
    gnutls_x509_crt_init(3) - API function
    gnutls_x509_crt_list_import(3) - API function
    gnutls_x509_crt_list_import2(3) - API function
    gnutls_x509_crt_list_import_pkcs11(3) - API function
    gnutls_x509_crt_list_import_url(3) - API function
    gnutls_x509_crt_list_verify(3) - API function
    gnutls_x509_crt_print(3) - API function
    gnutls_x509_crt_privkey_sign(3) - API function
    gnutls_x509_crt_set_activation_time(3) - API function
    gnutls_x509_crt_set_authority_info_access(3) - API function
    gnutls_x509_crt_set_authority_key_id(3) - API function
    gnutls_x509_crt_set_basic_constraints(3) - API function
    gnutls_x509_crt_set_ca_status(3) - API function
    gnutls_x509_crt_set_crl_dist_points(3) - API function
    gnutls_x509_crt_set_crl_dist_points2(3) - API function
    gnutls_x509_crt_set_crq(3) - API function
    gnutls_x509_crt_set_crq_extension_by_oid(3) - API function
    gnutls_x509_crt_set_crq_extensions(3) - API function
    gnutls_x509_crt_set_dn(3) - API function
    gnutls_x509_crt_set_dn_by_oid(3) - API function
    gnutls_x509_crt_set_expiration_time(3) - API function
    gnutls_x509_crt_set_extension_by_oid(3) - API function
    gnutls_x509_crt_set_flags(3) - API function
    gnutls_x509_crt_set_inhibit_anypolicy(3) - API function
    gnutls_x509_crt_set_issuer_alt_name(3) - API function
    gnutls_x509_crt_set_issuer_alt_othername(3) - API function
    gnutls_x509_crt_set_issuer_dn(3) - API function
    gnutls_x509_crt_set_issuer_dn_by_oid(3) - API function
    gnutls_x509_crt_set_issuer_unique_id(3) - API function
    gnutls_x509_crt_set_key(3) - API function
    gnutls_x509_crt_set_key_purpose_oid(3) - API function
    gnutls_x509_crt_set_key_usage(3) - API function
    gnutls_x509_crt_set_name_constraints(3) - API function
    gnutls_x509_crt_set_pin_function(3) - API function
    gnutls_x509_crt_set_policy(3) - API function
    gnutls_x509_crt_set_private_key_usage_period(3) - API function
    gnutls_x509_crt_set_proxy(3) - API function
    gnutls_x509_crt_set_proxy_dn(3) - API function
    gnutls_x509_crt_set_pubkey(3) - API function
    gnutls_x509_crt_set_serial(3) - API function
    gnutls_x509_crt_set_spki(3) - API function
    gnutls_x509_crt_set_subject_alternative_name(3) - API function
    gnutls_x509_crt_set_subject_alt_name(3) - API function
    gnutls_x509_crt_set_subject_alt_othername(3) - API function
    gnutls_x509_crt_set_subject_key_id(3) - API function
    gnutls_x509_crt_set_subject_unique_id(3) - API function
    gnutls_x509_crt_set_tlsfeatures(3) - API function
    gnutls_x509_crt_set_version(3) - API function
    gnutls_x509_crt_sign(3) - API function
    gnutls_x509_crt_sign2(3) - API function
    gnutls_x509_crt_verify(3) - API function
    gnutls_x509_crt_verify_data2(3) - API function
    gnutls_x509_dn_deinit(3) - API function
    gnutls_x509_dn_export(3) - API function
    gnutls_x509_dn_export2(3) - API function
    gnutls_x509_dn_get_rdn_ava(3) - API function
    gnutls_x509_dn_get_str(3) - API function
    gnutls_x509_dn_get_str2(3) - API function
    gnutls_x509_dn_import(3) - API function
    gnutls_x509_dn_init(3) - API function
    gnutls_x509_dn_oid_known(3) - API function
    gnutls_x509_dn_oid_name(3) - API function
    gnutls_x509_dn_set_str(3) - API function
    gnutls_x509_ext_deinit(3) - API function
    gnutls_x509_ext_export_aia(3) - API function
    gnutls_x509_ext_export_authority_key_id(3) - API function
    gnutls_x509_ext_export_basic_constraints(3) - API function
    gnutls_x509_ext_export_crl_dist_points(3) - API function
    gnutls_x509_ext_export_inhibit_anypolicy(3) - API function
    gnutls_x509_ext_export_key_purposes(3) - API function
    gnutls_x509_ext_export_key_usage(3) - API function
    gnutls_x509_ext_export_name_constraints(3) - API function
    gnutls_x509_ext_export_policies(3) - API function
    gnutls_x509_ext_export_private_key_usage_period(3) - API function
    gnutls_x509_ext_export_proxy(3) - API function
    gnutls_x509_ext_export_subject_alt_names(3) - API function
    gnutls_x509_ext_export_subject_key_id(3) - API function
    gnutls_x509_ext_export_tlsfeatures(3) - API function
    gnutls_x509_ext_import_aia(3) - API function
    gnutls_x509_ext_import_authority_key_id(3) - API function
    gnutls_x509_ext_import_basic_constraints(3) - API function
    gnutls_x509_ext_import_crl_dist_points(3) - API function
    gnutls_x509_ext_import_inhibit_anypolicy(3) - API function
    gnutls_x509_ext_import_key_purposes(3) - API function
    gnutls_x509_ext_import_key_usage(3) - API function
    gnutls_x509_ext_import_name_constraints(3) - API function
    gnutls_x509_ext_import_policies(3) - API function
    gnutls_x509_ext_import_private_key_usage_period(3) - API function
    gnutls_x509_ext_import_proxy(3) - API function
    gnutls_x509_ext_import_subject_alt_names(3) - API function
    gnutls_x509_ext_import_subject_key_id(3) - API function
    gnutls_x509_ext_import_tlsfeatures(3) - API function
    gnutls_x509_ext_print(3) - API function
    gnutls_x509_key_purpose_deinit(3) - API function
    gnutls_x509_key_purpose_get(3) - API function
    gnutls_x509_key_purpose_init(3) - API function
    gnutls_x509_key_purpose_set(3) - API function
    gnutls_x509_name_constraints_add_excluded(3) - API function
    gnutls_x509_name_constraints_add_permitted(3) - API function
    gnutls_x509_name_constraints_check(3) - API function
    gnutls_x509_name_constraints_check_crt(3) - API function
    gnutls_x509_name_constraints_deinit(3) - API function
    gnutls_x509_name_constraints_get_excluded(3) - API function
    gnutls_x509_name_constraints_get_permitted(3) - API function
    gnutls_x509_name_constraints_init(3) - API function
    gnutls_x509_othername_to_virtual(3) - API function
    gnutls_x509_policies_deinit(3) - API function
    gnutls_x509_policies_get(3) - API function
    gnutls_x509_policies_init(3) - API function
    gnutls_x509_policies_set(3) - API function
    gnutls_x509_policy_release(3) - API function
    gnutls_x509_privkey_cpy(3) - API function
    gnutls_x509_privkey_deinit(3) - API function
    gnutls_x509_privkey_export(3) - API function
    gnutls_x509_privkey_export2(3) - API function
    gnutls_x509_privkey_export2_pkcs8(3) - API function
    gnutls_x509_privkey_export_dsa_raw(3) - API function
    gnutls_x509_privkey_export_ecc_raw(3) - API function
    gnutls_x509_privkey_export_gost_raw(3) - API function
    gnutls_x509_privkey_export_pkcs8(3) - API function
    gnutls_x509_privkey_export_rsa_raw(3) - API function
    gnutls_x509_privkey_export_rsa_raw2(3) - API function
    gnutls_x509_privkey_fix(3) - API function
    gnutls_x509_privkey_generate(3) - API function
    gnutls_x509_privkey_generate2(3) - API function
    gnutls_x509_privkey_get_key_id(3) - API function
    gnutls_x509_privkey_get_pk_algorithm(3) - API function
    gnutls_x509_privkey_get_pk_algorithm2(3) - API function
    gnutls_x509_privkey_get_seed(3) - API function
    gnutls_x509_privkey_get_spki(3) - API function
    gnutls_x509_privkey_import(3) - API function
    gnutls_x509_privkey_import2(3) - API function
    gnutls_x509_privkey_import_dsa_raw(3) - API function
    gnutls_x509_privkey_import_ecc_raw(3) - API function
    gnutls_x509_privkey_import_gost_raw(3) - API function
    gnutls_x509_privkey_import_openssl(3) - API function
    gnutls_x509_privkey_import_pkcs8(3) - API function
    gnutls_x509_privkey_import_rsa_raw(3) - API function
    gnutls_x509_privkey_import_rsa_raw2(3) - API function
    gnutls_x509_privkey_init(3) - API function
    gnutls_x509_privkey_sec_param(3) - API function
    gnutls_x509_privkey_set_flags(3) - API function
    gnutls_x509_privkey_set_pin_function(3) - API function
    gnutls_x509_privkey_set_spki(3) - API function
    gnutls_x509_privkey_sign_data(3) - API function
    gnutls_x509_privkey_sign_hash(3) - API function
    gnutls_x509_privkey_verify_params(3) - API function
    gnutls_x509_privkey_verify_seed(3) - API function
    gnutls_x509_rdn_get(3) - API function
    gnutls_x509_rdn_get2(3) - API function
    gnutls_x509_rdn_get_by_oid(3) - API function
    gnutls_x509_rdn_get_oid(3) - API function
    gnutls_x509_spki_deinit(3) - API function
    gnutls_x509_spki_get_rsa_pss_params(3) - API function
    gnutls_x509_spki_init(3) - API function
    gnutls_x509_spki_set_rsa_pss_params(3) - API function
    gnutls_x509_tlsfeatures_add(3) - API function
    gnutls_x509_tlsfeatures_check_crt(3) - API function
    gnutls_x509_tlsfeatures_deinit(3) - API function
    gnutls_x509_tlsfeatures_get(3) - API function
    gnutls_x509_tlsfeatures_init(3) - API function
    gnutls_x509_trust_list_add_cas(3) - API function
    gnutls_x509_trust_list_add_crls(3) - API function
    gnutls_x509_trust_list_add_named_crt(3) - API function
    gnutls_x509_trust_list_add_system_trust(3) -
    gnutls_x509_trust_list_add_trust_dir(3) - API function
    gnutls_x509_trust_list_add_trust_file(3) - API function
    gnutls_x509_trust_list_add_trust_mem(3) - API function
    gnutls_x509_trust_list_deinit(3) - API function
    gnutls_x509_trust_list_get_issuer(3) - API function
    gnutls_x509_trust_list_get_issuer_by_dn(3) - API function
    gnutls_x509_trust_list_get_issuer_by_subject_key_id(3) - API function
    gnutls_x509_trust_list_init(3) - API function
    gnutls_x509_trust_list_iter_deinit(3) - API function
    gnutls_x509_trust_list_iter_get_ca(3) - API function
    gnutls_x509_trust_list_remove_cas(3) - API function
    gnutls_x509_trust_list_remove_trust_file(3) - API function
    gnutls_x509_trust_list_remove_trust_mem(3) - API function
    gnutls_x509_trust_list_verify_crt(3) - API function
    gnutls_x509_trust_list_verify_crt2(3) - API function
    gnutls_x509_trust_list_verify_named_crt(3) - API function
    gpasswd(1) - administer /etc/group and /etc/gshadow
    gperl(1) - groff preprocessor for Perl parts in roff files
    gpinyin(1) - Chinese European-like writing within groff
    gprof(1) - display call graph profile data
    grantpt(3) - grant access to the slave pseudoterminal
    grantpt(3p) - terminal device
    grap2graph(1) - convert a grap diagram into a cropped bitmap image
    grep(1) - print lines that match patterns
    grep(1p) - search a file for a pattern
    grn(1) - groff preprocessor for gremlin files
    grodvi(1) - convert groff output to TeX DVI format
    groff(1) - front-end for the groff document formatting system
    groff(7) - a short reference for the GNU roff language
    groff_char(7) - groff glyph names
    groff_diff(7) - differences between GNU troff and classical troff
    groffer(1) - display groff files and man pages on X and tty
    groff_filenames(5) - filename extensions for roff and groff
    groff_font(5) - format of groff device and font description files
    groff_hdtbl(7) - Heidelberger table macros for GNU roff
    groff_man(7) - GNU roff macro package for formatting man pages
    groff_me(7) - “me” macro package for formatting documents with GNU roff
    groff_mm(7) - memorandum macros for GNU roff
    groff_mmse(7) -
    groff_mom(7) - groff “mom” macros; “mom” is a “roff” language, part of “groff”
    groff_ms(7) - GNU roff manuscript macro package for formatting documents
    groff_out(5) - groff intermediate output format
    groff_tmac(5) - macro files in the roff typesetting system
    groff_trace(7) - groff macro package trace.tmac
    groff_www(7) - groff macros for authoring web pages
    grog(1) - guess options for a following groff command
    grohtml(1) - HTML driver for groff
    grolbp(1) - groff driver for Canon CAPSL printers (LBP-4 and LBP-8 series laser printers).
    grolj4(1) - groff driver for HP Laserjet 4 family
    gropdf(1) - PDF driver for groff
    grops(1) - PostScript driver for groff
    grotty(1) - groff driver for typewriter-like devices
    group(5) - user group file
    group.conf(5) - configuration file for the pam_group module
    groupadd(8) - create a new group
    groupdel(8) - delete a group
    group_member(3) - test whether a process is in a group
    groupmems(8) - administer members of a user's primary group
    groupmod(8) - modify a group definition on the system
    groups(1) - print the groups a user is in
    grp.h(0p) - group structure
    grpck(8) - verify integrity of group files
    grpconv(8) - convert to and from shadow passwords and groups
    grpunconv(8) - convert to and from shadow passwords and groups
    gshadow(5) - shadowed group file
    gsignal(3) - software signal facility
    gssd(8) - RPCSEC_GSS daemon
    gtty(2) - unimplemented system calls
    guards(1) - select from a list of files guarded by conditions

top
    halfdelay(3x) - curses input options
    halt(8) - Halt, power-off or reboot the machine
    handle(3) - file handle operations
    handle_to_fshandle(3) - file handle operations
    has_colors(3x) - curses color manipulation routines
    hash(1p) - remember or report utility locations
    hash(3) - hash database access method
    has_ic(3x) - curses environment query routines
    has_il(3x) - curses environment query routines
    has_key(3x) - get (or push back) characters from curses terminal keyboard
    hasmntopt(3) - get filesystem descriptor file entry
    has_mouse(3x) - mouse interface through curses
    hcreate(3) - hash table management
    hcreate(3p) - manage hash search table
    hcreate_r(3) - hash table management
    hd(4) - MFM/IDE hard disk devices
    hdestroy(3) - hash table management
    hdestroy(3p) - manage hash search table
    hdestroy_r(3) - hash table management
    hdparm(8) - get/set SATA/IDE device parameters
    head(1) - output the first part of files
    head(1p) - copy the first part of files
    h_errno(3) - get network host entry
    herror(3) - get network host entry
    hexdump(1) - display file contents in hexadecimal, decimal, octal, or ascii
    HFSC(8) - Hierarchical Fair Service Curve's control under linux
    hg(1) - Mercurial source code management system
    hgignore(5) - syntax for Mercurial ignore files
    hgrc(5) - configuration files for Mercurial
    hier(7) - description of the filesystem hierarchy
    history(3) - GNU History Library
    hline(3x) - create curses borders, horizontal and vertical lines
    hline_set(3x) - create curses borders or lines using complex characters and renditions
    host.conf(5) - resolver configuration file
    hostid(1) - print the numeric identifier for the current host
    hostname(1) - show or set the system's host name
    hostname(5) - Local hostname configuration file
    hostname(7) - hostname resolution description
    hostnamectl(1) - Control the system hostname
    hosts(5) - static table lookup for hostnames
    hosts.equiv(5) - list of hosts and users that are granted "trusted" r command access to your system
    hpftodit(1) - create font description files for use with groff -Tlj4
    hpsa(4) - HP Smart Array SCSI driver
    hsearch(3) - hash table management
    hsearch(3p) - manage hash search table
    hsearch_r(3) - hash table management
    hstrerror(3) - get network host entry
    HTB(8) - Hierarchy Token Bucket
    htobe16(3) - convert values between host and big-/little-endian byte order
    htobe32(3) - convert values between host and big-/little-endian byte order
    htobe64(3) - convert values between host and big-/little-endian byte order
    htole16(3) - convert values between host and big-/little-endian byte order
    htole32(3) - convert values between host and big-/little-endian byte order
    htole64(3) - convert values between host and big-/little-endian byte order
    htonl(3) - convert values between host and network byte order
    htonl(3p) - convert values between host and network byte order
    htons(3) - convert values between host and network byte order
    htons(3p) - convert values between host and network byte order
    htop(1) - interactive process viewer
    HUGE_VAL(3) - floating-point constants
    huge_val(3) - floating-point constants
    HUGE_VALF(3) - floating-point constants
    huge_valf(3) - floating-point constants
    HUGE_VALL(3) - floating-point constants
    huge_vall(3) - floating-point constants
    hwclock(8) - time clocks utility
    hwdb(7) - Hardware Database
    hypot(3) - Euclidean distance function
    hypot(3p) - Euclidean distance function
    hypotf(3) - Euclidean distance function
    hypotf(3p) - Euclidean distance function
    hypotl(3) - Euclidean distance function
    hypotl(3p) - Euclidean distance function

top
    i386(8) - change reported architecture in new program environment and/or set personality flags
    ibacm(1) - address and route resolution services for InfiniBand.
    ibacm(7) - InfiniBand communication management assistant
    ib_acme(1) - test and configuration utility for the IB ACM
    ibsrpdm(1) - Discover SRP targets on an InfiniBand Fabric
    ibv_ack_async_event(3) - get or acknowledge asynchronous events
    ibv_ack_cq_events(3) - get and acknowledge completion queue (CQ) events
    ibv_alloc_dm(3) - allocate or free a device memory buffer (DMs) and perform memory copy to or from it
    ibv_alloc_mw(3) - allocate or deallocate a memory window (MW)
    ibv_alloc_parent_domain(3) - allocate and deallocate the parent domain object
    ibv_alloc_pd(3) - allocate or deallocate a protection domain (PDs)
    ibv_alloc_td(3) - allocate and deallocate thread domain object
    ibv_asyncwatch(1) - display asynchronous events
    ibv_bind_mw(3) - post a request to bind a type 1 memory window to a memory region
    ibv_close_device(3) - open and close an RDMA device context
    ibv_close_xrcd(3) - open or close an XRC protection domain (XRCDs)
    ibv_create_ah(3) - create or destroy an address handle (AH)
    ibv_create_ah_from_wc(3) - initialize or create an address handle (AH) from a work completion
    ibv_create_comp_channel(3) - create or destroy a completion event channel
    ibv_create_cq(3) - create or destroy a completion queue (CQ)
    ibv_create_cq_ex(3) - create a completion queue (CQ)
    ibv_create_flow(3) - create or destroy flow steering rules
    ibv_create_qp(3) - create or destroy a queue pair (QP)
    ibv_create_qp_ex(3) - create or destroy a queue pair (QP)
    ibv_create_rwq_ind_table(3) - create or destroy a Receive Work Queue Indirection Table (RWQ IND TBL).
    ibv_create_srq(3) - create or destroy a shared receive queue (SRQ)
    ibv_create_srq_ex(3) - create or destroy a shared receive queue (SRQ)
    ibv_create_wq(3) - create or destroy a Work Queue (WQ).
    ibv_dealloc_mw(3) - allocate or deallocate a memory window (MW)
    ibv_dealloc_pd(3) - allocate or deallocate a protection domain (PDs)
    ibv_dereg_mr(3) - register or deregister a memory region (MR)
    ibv_destroy_ah(3) - create or destroy an address handle (AH)
    ibv_destroy_comp_channel(3) - create or destroy a completion event channel
    ibv_destroy_cq(3) - create or destroy a completion queue (CQ)
    ibv_destroy_flow(3) - create or destroy flow steering rules
    ibv_destroy_qp(3) - create or destroy a queue pair (QP)
    ibv_destroy_rwq_ind_table(3) - create or destroy a Receive Work Queue Indirection Table (RWQ IND TBL).
    ibv_destroy_srq(3) - create or destroy a shared receive queue (SRQ)
    ibv_destroy_wq(3) - create or destroy a Work Queue (WQ).
    ibv_devices(1) - list RDMA devices
    ibv_devinfo(1) - query RDMA devices
    ibv_get_async_event(3) - get or acknowledge asynchronous events
    ibv_get_cq_event(3) - get and acknowledge completion queue (CQ) events
    ibv_init_ah_from_wc(3) - initialize or create an address handle (AH) from a work completion
    ibv_modify_cq(3) - modify a completion queue (CQ)
    ibv_modify_qp(3) - modify the attributes of a queue pair (QP)
    ibv_modify_qp_rate_limit(3) - modify the send rate limits attributes of a queue pair (QP)
    ibv_modify_srq(3) - modify attributes of a shared receive queue (SRQ)
    ibv_modify_wq(3) - Modify a Work Queue (WQ).
    ibv_open_device(3) - open and close an RDMA device context
    ibv_open_qp(3) - open a shareable queue pair (QP)
    ibv_open_xrcd(3) - open or close an XRC protection domain (XRCDs)
    ibv_poll_cq(3) - poll a completion queue (CQ)
    ibv_post_recv(3) - post a list of work requests (WRs) to a receive queue
    ibv_post_send(3) - post a list of work requests (WRs) to a send queue
    ibv_post_srq_ops(3) - perform on a special shared receive queue (SRQ) configuration manipulations
    ibv_post_srq_recv(3) - post a list of work requests (WRs) to a shared receive queue (SRQ)
    ibv_query_device(3) - query an RDMA device's attributes
    ibv_query_device_ex(3) - query an RDMA device's attributes
    ibv_query_port(3) - query an RDMA port's attributes
    ibv_query_qp(3) - get the attributes of a queue pair (QP)
    ibv_query_rt_values_ex(3) - query an RDMA device for some real time values
    ibv_query_srq(3) - get the attributes of a shared receive queue (SRQ)
    ibv_rc_pingpong(1) - simple InfiniBand RC transport test
    ibv_reg_mr(3) - register or deregister a memory region (MR)
    ibv_srq_pingpong(1) - simple InfiniBand shared receive queue test
    ibv_uc_pingpong(1) - simple InfiniBand UC transport test
    ibv_ud_pingpong(1) - simple InfiniBand UD transport test
    ibv_xsrq_pingpong(1) - simple InfiniBand shared receive queue test
    icmp(7) - Linux IPv4 ICMP kernel module.
    iconv(1) - convert text from one character encoding to another
    iconv(1p) - codeset conversion
    iconv(3) - perform character set conversion
    iconv(3p) - codeset conversion function
    iconv.h(0p) - codeset conversion facility
    iconv_close(3) - deallocate descriptor for character set conversion
    iconv_close(3p) - codeset conversion deallocation function
    iconvconfig(8) - create iconv module configuration cache
    iconv_open(3) - allocate descriptor for character set conversion
    iconv_open(3p) - codeset conversion allocation function
    id(1) - print real and effective user and group IDs
    id(1p) - return user identity
    idcok(3x) - curses output options
    idle(2) - make process 0 idle
    idlok(3x) - curses output options
    idmapd(8) - > Name Mapper
    ifcfg(8) - simplistic script which replaces ifconfig IP management
    ifconfig(8) - configure a network interface
    IFE(8) - encapsulate/decapsulate metadata
    if_freenameindex(3) - get network interface names and indexes
    if_freenameindex(3p) - free memory allocated by if_nameindex
    if_indextoname(3) - mappings between network interface names and indexes
    if_indextoname(3p) - map a network interface index to its corresponding name
    if_nameindex(3) - get network interface names and indexes
    if_nameindex(3p) - return all network interface names and indexes
    if_nametoindex(3) - mappings between network interface names and indexes
    if_nametoindex(3p) - map a network interface name to its corresponding index
    ifpps(8) - top-like networking and system statistics
    ifstat(8) - handy utility to read network interface statistics
    ilogb(3) - get integer exponent of a floating-point value
    ilogb(3p) - return an unbiased exponent
    ilogbf(3) - get integer exponent of a floating-point value
    ilogbf(3p) - return an unbiased exponent
    ilogbl(3) - get integer exponent of a floating-point value
    ilogbl(3p) - return an unbiased exponent
    imaxabs(3) - compute the absolute value of an integer
    imaxabs(3p) - return absolute value
    imaxdiv(3) - compute quotient and remainder of an integer division
    imaxdiv(3p) - return quotient and remainder
    immedok(3x) - curses output options
    inb(2) - port I/O
    inb_p(2) - port I/O
    inch(3x) - get a character and attributes from a curses window
    inchnstr(3x) - get a string of characters (and attributes) from a curses window
    inchstr(3x) - get a string of characters (and attributes) from a curses window
    indent(1) - changes the appearance of a C program by inserting or deleting whitespace.
    index(3) - locate character in string
    indxbib(1) - make inverted index for bibliographic databases
    inet(3) - Internet address manipulation routines
    inet_addr(3) - Internet address manipulation routines
    inet_addr(3p) - IPv4 address manipulation
    inet_aton(3) - Internet address manipulation routines
    inet_lnaof(3) - Internet address manipulation routines
    inet_makeaddr(3) - Internet address manipulation routines
    inet_net_ntop(3) - Internet network number conversion
    inet_netof(3) - Internet address manipulation routines
    inet_net_pton(3) - Internet network number conversion
    inet_network(3) - Internet address manipulation routines
    inet_ntoa(3) - Internet address manipulation routines
    inet_ntoa(3p) - IPv4 address manipulation
    inet_ntop(3) - convert IPv4 and IPv6 addresses from binary to text form
    inet_ntop(3p) - convert IPv4 and IPv6 addresses between binary and text form
    inet_pton(3) - convert IPv4 and IPv6 addresses from text to binary form
    inet_pton(3p) - convert IPv4 and IPv6 addresses between binary and text form
    INFINITY(3) - floating-point constants
    infinity(3) - floating-point constants
    init(1) - systemd system and service manager
    init_color(3x) - curses color manipulation routines
    initgroups(3) - initialize the supplementary group access list
    init_module(2) - load a kernel module
    init_pair(3x) - curses color manipulation routines
    initrd(4) - boot loader initialized RAM disk
    initscr(3x) - curses screen initialization and manipulation routines
    init_selinuxmnt(3) - initialize the global variable selinux_mnt
    initstate(3) - random number generator
    initstate(3p) - random number functions
    initstate_r(3) - reentrant random number generator
    inl(2) - port I/O
    inl_p(2) - port I/O
    innetgr(3) - handle network group entries
    innochecksum(1) - offline InnoDB file checksum utility
    innstr(3x) - get a string of characters from a curses window
    innwstr(3x) - get a string of wchar_t characters from a curses window
    inode(7) - file inode information
    inotify(7) - monitoring filesystem events
    inotify_add_watch(2) - add a watch to an initialized inotify instance
    inotify_init(2) - initialize an inotify instance
    inotify_init1(2) - initialize an inotify instance
    inotify_rm_watch(2) - remove an existing watch from an inotify instance
    inotifywait(1) - wait for changes to files using inotify
    inotifywatch(1) - gather filesystem access statistics using inotify
    insb(2) - port I/O
    insch(3x) - insert a character before cursor in a curses window
    insdelln(3x) - delete and insert lines in a curses window
    insertln(3x) - delete and insert lines in a curses window
    insl(2) - port I/O
    insmod(8) - Simple program to insert a module into the Linux Kernel
    insnstr(3x) - insert string before cursor in a curses window
    ins_nwstr(3x) - insert a wide-character string into a curses window
    insque(3) - insert/remove an item from a queue
    insque(3p) - insert or remove an element in a queue
    insstr(3x) - insert string before cursor in a curses window
    install(1) - copy files and set attributes
    instr(3x) - get a string of characters from a curses window
    insw(2) - port I/O
    ins_wch(3x) - insert a complex character and rendition into a window
    ins_wstr(3x) - insert a wide-character string into a curses window
    integritysetup(8) - manage dm-integrity (block level integrity) volumes
    intrflush(3x) - curses input options
    intro(1) - introduction to user commands
    intro(2) - introduction to system calls
    intro(3) - introduction to library functions
    intro(4) - introduction to special files
    intro(5) - introduction to file formats and filesystems
    intro(6) - introduction to games
    intro(7) - introduction to overview and miscellany section
    intro(8) - introduction to administration and privileged commands
    inttypes.h(0p) - fixed size integer types
    inw(2) - port I/O
    in_wch(3x) - extract a complex character and rendition from a window
    in_wchnstr(3x) - get an array of complex characters and renditions from a curses window
    in_wchstr(3x) - get an array of complex characters and renditions from a curses window
    inw_p(2) - port I/O
    inwstr(3x) - get a string of wchar_t characters from a curses window
    io_cancel(2) - cancel an outstanding asynchronous I/O operation
    ioctl(2) - control device
    ioctl(3p) - control a STREAMS device (STREAMS)
    ioctl_console(2) - ioctls for console terminal and virtual consoles
    ioctl_fat(2) - manipulating the FAT filesystem
    ioctl_ficlone(2) - share some the data of one file with another file
    ioctl_ficlonerange(2) - share some the data of one file with another file
    ioctl_fideduperange(2) - share some the data of one file with another file
    ioctl_getfsmap(2) - retrieve the physical layout of the filesystem
    ioctl_iflags(2) - ioctl() operations for inode flags
    ioctl_list(2) - list of ioctl calls in Linux/i386 kernel
    ioctl_ns(2) - ioctl() operations for Linux namespaces
    ioctl_tty(2) - ioctls for terminals and serial lines
    ioctl_userfaultfd(2) - create a file descriptor for handling page faults in user space
    ioctl_xfs_scrub_metadata(2) - check XFS filesystem metadata
    io_destroy(2) - destroy an asynchronous I/O context
    io_getevents(2) - read asynchronous I/O events from the completion queue
    ionice(1) - set or get process I/O scheduling class and priority
    ioperm(2) - set port input/output permissions
    iopl(2) - change I/O privilege level
    ioprio_get(2) - get/set I/O scheduling class and priority
    ioprio_set(2) - get/set I/O scheduling class and priority
    io_setup(2) - create an asynchronous I/O context
    iostat(1) - Report Central Processing Unit (CPU) statistics and input/output statistics for devices and partitions.
    iostat2pcp(1) - import iostat data and create a PCP archive
    io_submit(2) - submit asynchronous I/O blocks for processing
    iotop(8) - simple top-like I/O monitor
    iowatcher(1) - Create visualizations from blktrace results
    ip-addrlabel(8) - protocol address label management
    ip-fou(8) - Foo-over-UDP receive port configuration
    ip-gue(8) - Foo-over-UDP receive port configuration
    ip-l2tp(8) - L2TPv3 static unmanaged tunnel configuration
    ip-macsec(8) - MACsec device configuration
    ip-maddress(8) - multicast addresses management
    ip-monitor(8) - state monitoring
    ip-mroute(8) - multicast routing cache management
    ip-neighbour(8) - neighbour/arp tables management.
    ip-netconf(8) - network configuration monitoring
    ip-netns(8) - process network namespace management
    ip-ntable(8) - neighbour table configuration
    ip-rule(8) - routing policy database management
    ip-sr(8) - IPv6 Segment Routing management
    ip-tcp_metrics(8) - management for TCP Metrics
    ip-token(8) - tokenized interface identifier support
    ip-tunnel(8) - tunnel configuration
    ip-vrf(8) - run a command against a vrf
    ip-xfrm(8) - transform configuration
    ip(7) - Linux IPv4 protocol implementation
    ip(8) - show / manipulate routing, network devices, interfaces and tunnels
    ip6tables-restore(8) - Restore IP Tables
    ip6tables-save(8) - dump iptables rules
    ip6tables(8) - administration tool for IPv4/IPv6 packet filtering and NAT
    ipc(2) - System V IPC system calls
    ipc(5) - System V interprocess communication mechanisms
    ipcmk(1) - make various IPC resources
    ipcrm(1) - remove certain IPC resources
    ipcrm(1p) - remove an XSI message queue, semaphore set, or shared memory segment identifier
    ipcs(1) - show information on IPC facilities
    ipcs(1p) - report XSI interprocess communication facilities status
    ipg(8) - send stream of UDP packets
    ippfind(1) - find internet printing protocol printers
    ipptool(1) - perform internet printing protocol requests
    ipptoolfile(5) - ipptool file format
    iptables-apply(8) - a safer way to update iptables remotely
    iptables-extensions(8) - list of extensions in the standard iptables distribution
    iptables-restore(8) - Restore IP Tables
    iptables-save(8) - dump iptables rules
    iptables-xml(1) - Convert iptables-save format to XML
    iptables(8) - administration tool for IPv4/IPv6 packet filtering and NAT
    iptraf-ng(8) - Interactive Colorful IP LAN Monitor
    iptraf(8) - Interactive Colorful IP LAN Monitor
    ipv6(7) - Linux IPv6 protocol implementation
    iruserok(3) - routines for returning a stream to a remote command
    iruserok_af(3) - routines for returning a stream to a remote command
    isalnum(3) - character classification functions
    isalnum(3p) - test for an alphanumeric character
    isalnum_l(3) - character classification functions
    isalnum_l(3p) - test for an alphanumeric character
    isalpha(3) - character classification functions
    isalpha(3p) - test for an alphabetic character
    isalpha_l(3) - character classification functions
    isalpha_l(3p) - test for an alphabetic character
    isascii(3) - character classification functions
    isascii(3p) - bit US-ASCII character
    isascii_l(3) - character classification functions
    isastream(2) - unimplemented system calls
    isastream(3p) - test a file descriptor (STREAMS)
    isatty(3) - test whether a file descriptor refers to a terminal
    isatty(3p) - test for a terminal device
    isblank(3) - character classification functions
    isblank(3p) - test for a blank character
    isblank_l(3) - character classification functions
    isblank_l(3p) - test for a blank character
    is_cleared(3x) - curses window properties
    iscntrl(3) - character classification functions
    iscntrl(3p) - test for a control character
    iscntrl_l(3) - character classification functions
    iscntrl_l(3p) - test for a control character
    is_context_customizable(3) - check whether SELinux context type is customizable by the administrator
    isdigit(3) - character classification functions
    isdigit(3p) - test for a decimal digit
    isdigit_l(3) - character classification functions
    isdigit_l(3p) - test for a decimal digit
    isendwin(3x) - curses screen initialization and manipulation routines
    isfdtype(3) - test file type of a file descriptor
    isfinite(3) - floating-point classification macros
    isfinite(3p) - test for finite value
    isgraph(3) - character classification functions
    isgraph(3p) - test for a visible character
    isgraph_l(3) - character classification functions
    isgraph_l(3p) - test for a visible character
    isgreater(3) - floating-point relational tests without exception for NaN
    isgreater(3p) - test if x greater than y
    isgreaterequal(3) - floating-point relational tests without exception for NaN
    isgreaterequal(3p) - test if x is greater than or equal to y
    is_idcok(3x) - curses window properties
    is_idlok(3x) - curses window properties
    is_immedok(3x) - curses window properties
    isinf(3) - floating-point classification macros
    isinf(3p) - test for infinity
    isinff(3) - BSD floating-point classification functions
    isinfl(3) - BSD floating-point classification functions
    is_keypad(3x) - curses window properties
    is_leaveok(3x) - curses window properties
    isless(3) - floating-point relational tests without exception for NaN
    isless(3p) - test if x is less than y
    islessequal(3) - floating-point relational tests without exception for NaN
    islessequal(3p) - test if x is less than or equal to y
    islessgreater(3) - floating-point relational tests without exception for NaN
    islessgreater(3p) - test if x is less than or greater than y
    is_linetouched(3x) - curses refresh control routines
    islower(3) - character classification functions
    islower(3p) - test for a lowercase letter
    islower_l(3) - character classification functions
    islower_l(3p) - test for a lowercase letter
    isnan(3) - floating-point classification macros
    isnan(3p) - test for a NaN
    isnanf(3) - BSD floating-point classification functions
    isnanl(3) - BSD floating-point classification functions
    is_nodelay(3x) - curses window properties
    isnormal(3) - floating-point classification macros
    isnormal(3p) - test for a normal value
    is_notimeout(3x) - curses window properties
    iso-8859-1(7) - ISO 8859-1 character set encoded in octal, decimal, and hexadecimal
    iso-8859-10(7) - ISO 8859-10 character set encoded in octal, decimal, and hexadecimal
    iso-8859-11(7) - ISO 8859-11 character set encoded in octal, decimal, and hexadecimal
    iso-8859-13(7) - ISO 8859-13 character set encoded in octal, decimal, and hexadecimal
    iso-8859-14(7) - ISO 8859-14 character set encoded in octal, decimal, and hexadecimal
    iso-8859-15(7) - ISO 8859-15 character set encoded in octal, decimal, and hexadecimal
    iso-8859-16(7) - ISO 8859-16 character set encoded in octal, decimal, and hexadecimal
    iso-8859-2(7) - ISO 8859-2 character set encoded in octal, decimal, and hexadecimal
    iso-8859-3(7) - ISO 8859-3 character set encoded in octal, decimal, and hexadecimal
    iso-8859-4(7) - ISO 8859-4 character set encoded in octal, decimal, and hexadecimal
    iso-8859-5(7) - ISO 8859-5 character set encoded in octal, decimal, and hexadecimal
    iso-8859-6(7) - ISO 8859-6 character set encoded in octal, decimal, and hexadecimal
    iso-8859-7(7) - ISO 8859-7 character set encoded in octal, decimal, and hexadecimal
    iso-8859-8(7) - ISO 8859-8 character set encoded in octal, decimal, and hexadecimal
    iso-8859-9(7) - ISO 8859-9 character set encoded in octal, decimal, and hexadecimal
    iso646.h(0p) - alternative spellings
    iso_8859-1(7) - ISO 8859-1 character set encoded in octal, decimal, and hexadecimal
    iso_8859-10(7) - ISO 8859-10 character set encoded in octal, decimal, and hexadecimal
    iso_8859-11(7) - ISO 8859-11 character set encoded in octal, decimal, and hexadecimal
    iso_8859-13(7) - ISO 8859-13 character set encoded in octal, decimal, and hexadecimal
    iso_8859-14(7) - ISO 8859-14 character set encoded in octal, decimal, and hexadecimal
    iso_8859-15(7) - ISO 8859-15 character set encoded in octal, decimal, and hexadecimal
    iso_8859-16(7) - ISO 8859-16 character set encoded in octal, decimal, and hexadecimal
    iso_8859-2(7) - ISO 8859-2 character set encoded in octal, decimal, and hexadecimal
    iso_8859-3(7) - ISO 8859-3 character set encoded in octal, decimal, and hexadecimal
    iso_8859-4(7) - ISO 8859-4 character set encoded in octal, decimal, and hexadecimal
    iso_8859-5(7) - ISO 8859-5 character set encoded in octal, decimal, and hexadecimal
    iso_8859-6(7) - ISO 8859-6 character set encoded in octal, decimal, and hexadecimal
    iso_8859-7(7) - ISO 8859-7 character set encoded in octal, decimal, and hexadecimal
    iso_8859-8(7) - ISO 8859-8 character set encoded in octal, decimal, and hexadecimal
    iso_8859-9(7) - ISO 8859-9 character set encoded in octal, decimal, and hexadecimal
    iso_8859_1(7) - ISO 8859-1 character set encoded in octal, decimal, and hexadecimal
    iso_8859_10(7) - ISO 8859-10 character set encoded in octal, decimal, and hexadecimal
    iso_8859_11(7) - ISO 8859-11 character set encoded in octal, decimal, and hexadecimal
    iso_8859_13(7) - ISO 8859-13 character set encoded in octal, decimal, and hexadecimal
    iso_8859_14(7) - ISO 8859-14 character set encoded in octal, decimal, and hexadecimal
    iso_8859_15(7) - ISO 8859-15 character set encoded in octal, decimal, and hexadecimal
    iso_8859_16(7) - ISO 8859-16 character set encoded in octal, decimal, and hexadecimal
    iso_8859_2(7) - ISO 8859-2 character set encoded in octal, decimal, and hexadecimal
    iso_8859_3(7) - ISO 8859-3 character set encoded in octal, decimal, and hexadecimal
    iso_8859_4(7) - ISO 8859-4 character set encoded in octal, decimal, and hexadecimal
    iso_8859_5(7) - ISO 8859-5 character set encoded in octal, decimal, and hexadecimal
    iso_8859_6(7) - ISO 8859-6 character set encoded in octal, decimal, and hexadecimal
    iso_8859_7(7) - ISO 8859-7 character set encoded in octal, decimal, and hexadecimal
    iso_8859_8(7) - ISO 8859-8 character set encoded in octal, decimal, and hexadecimal
    iso_8859_9(7) - ISO 8859-9 character set encoded in octal, decimal, and hexadecimal
    isosize(8) - output the length of an iso9660 filesystem
    is_pad(3x) - curses window properties
    isprint(3) - character classification functions
    isprint(3p) - test for a printable character
    isprint_l(3) - character classification functions
    isprint_l(3p) - test for a printable character
    ispunct(3) - character classification functions
    ispunct(3p) - test for a punctuation character
    ispunct_l(3) - character classification functions
    ispunct_l(3p) - test for a punctuation character
    is_scrollok(3x) - curses window properties
    is_selinux_enabled(3) - check whether SELinux is enabled
    is_selinux_mls_enabled(3) - check whether SELinux is enabled
    isspace(3) - character classification functions
    isspace(3p) - space character
    isspace_l(3) - character classification functions
    isspace_l(3p) - space character
    is_subwin(3x) - curses window properties
    issue(5) - prelogin message and identification file
    is_syncok(3x) - curses window properties
    is_term_resized(3x) - change the curses terminal size
    isunordered(3) - floating-point relational tests without exception for NaN
    isunordered(3p) - test if arguments are unordered
    isupper(3) - character classification functions
    isupper(3p) - test for an uppercase letter
    isupper_l(3) - character classification functions
    isupper_l(3p) - test for an uppercase letter
    iswalnum(3) - test for alphanumeric wide character
    iswalnum(3p) - character code
    iswalnum_l(3p) - character code
    iswalpha(3) - test for alphabetic wide character
    iswalpha(3p) - character code
    iswalpha_l(3p) - character code
    iswblank(3) - test for whitespace wide character
    iswblank(3p) - character code
    iswblank_l(3p) - character code
    iswcntrl(3) - test for control wide character
    iswcntrl(3p) - character code
    iswcntrl_l(3p) - character code
    iswctype(3) - wide-character classification
    iswctype(3p) - test character for a specified class
    iswctype_l(3p) - test character for a specified class
    iswdigit(3) - test for decimal digit wide character
    iswdigit(3p) - character code
    iswdigit_l(3p) - character code
    iswgraph(3) - test for graphic wide character
    iswgraph(3p) - character code
    iswgraph_l(3p) - character code
    is_wintouched(3x) - curses refresh control routines
    iswlower(3) - test for lowercase wide character
    iswlower(3p) - character code
    iswlower_l(3p) - character code
    iswprint(3) - test for printing wide character
    iswprint(3p) - character code
    iswprint_l(3p) - character code
    iswpunct(3) - test for punctuation or symbolic wide character
    iswpunct(3p) - character code
    iswpunct_l(3p) - character code
    iswspace(3) - test for whitespace wide character
    iswspace(3p) - space wide-character code
    iswspace_l(3p) - space wide-character code
    iswupper(3) - test for uppercase wide character
    iswupper(3p) - character code
    iswupper_l(3p) - character code
    iswxdigit(3) - test for hexadecimal digit wide character
    iswxdigit(3p) - character code
    iswxdigit_l(3p) - character code
    isxdigit(3) - character classification functions
    isxdigit(3p) - test for a hexadecimal digit
    isxdigit_l(3) - character classification functions
    isxdigit_l(3p) - test for a hexadecimal digit
    item_count(3x) - make and break connections between items and menus
    item_description(3x) - get menu item name and description fields
    item_name(3x) - get menu item name and description fields
    item_opts(3x) - set and get menu item options
    item_opts_off(3x) - set and get menu item options
    item_opts_on(3x) - set and get menu item options
    item_userptr(3x) - associate application data with a menu item
    item_value(3x) - set and get menu item values

top
    j0(3) - Bessel functions of the first kind
    j0(3p) - Bessel functions of the first kind
    j0f(3) - Bessel functions of the first kind
    j0l(3) - Bessel functions of the first kind
    j1(3) - Bessel functions of the first kind
    j1(3p) - Bessel functions of the first kind
    j1f(3) - Bessel functions of the first kind
    j1l(3) - Bessel functions of the first kind
    jn(3) - Bessel functions of the first kind
    jn(3p) - Bessel functions of the first kind
    jnf(3) - Bessel functions of the first kind
    jnl(3) - Bessel functions of the first kind
    jobs(1p) - display status of jobs in the current session
    join(1) - join lines of two files on a common field
    join(1p) - relational database operator
    journalctl(1) - Query the systemd journal
    journald.conf(5) - Journal service configuration files
    journald.conf.d(5) - Journal service configuration files
    jrand48(3) - generate uniformly distributed pseudo-random numbers
    jrand48(3p) - random long signed integer
    jrand48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly

top
    kbd_mode(1) - report or set the keyboard mode
    kbdrate(8) - reset the keyboard repeat rate and delay time
    kcmp(2) - compare two processes to determine if they share a kernel resource
    kernel-command-line(7) - Kernel command line parameters
    kernel-install(8) - Add and remove kernel and initramfs images to and from /boot
    kernelshark(1) - graphical reader for trace-cmd(1) output
    kexec(8) - directly boot into a new kernel
    kexec_file_load(2) - load a new kernel for later execution
    kexec_load(2) - load a new kernel for later execution
    key.dns_resolver(8) - upcall for request-key to handle dns_resolver keys
    keybound(3x) - return definition of keycode
    keyctl(1) - key management facility control
    keyctl(2) - manipulate the kernel's key management facility
    keyctl(3) - key management function wrappers
    keyctl_assume_authority(3) - key instantiation functions
    keyctl_chown(3) - change the ownership of a key
    keyctl_clear(3) - clear a keyring
    keyctl_describe(3) - describe a key
    keyctl_dh_compute(3) - Compute a Diffie-Hellman shared secret or public key
    keyctl_dh_compute_kdf(3) - Compute a Diffie-Hellman shared secret or public key
    keyctl_get_keyring_ID(3) - get the ID of a special keyring
    keyctl_get_keyring_id(3) - get the ID of a special keyring
    keyctl_get_persistent(3) - get the persistent keyring for a user
    keyctl_get_security(3) - retrieve a key's security context
    keyctl_instantiate(3) - key instantiation functions
    keyctl_instantiate_iov(3) - key instantiation functions
    keyctl_invalidate(3) - invalidate a key
    keyctl_join_session_keyring(3) - join a different session keyring
    keyctl_link(3) - link/unlink a key to/from a keyring
    keyctl_negate(3) - key instantiation functions
    keyctl_read(3) - read a key
    keyctl_reject(3) - key instantiation functions
    keyctl_restrict_keyring(3) - restrict keys that may be linked to a keyring
    keyctl_revoke(3) - revoke a key
    keyctl_search(3) - search a keyring for a key
    keyctl_session_to_parent(3) - set the parent process's session keyring
    keyctl_setperm(3) - change the permissions mask on a key
    keyctl_set_reqkey_keyring(3) - set the implicit destination keyring
    keyctl_set_timeout(3) - set the expiration timer on a key
    keyctl_unlink(3) - link/unlink a key to/from a keyring
    keyctl_update(3) - update a key
    key_decryptsession(3) - interfaces to rpc keyserver daemon
    key_defined(3x) - check if a keycode is defined
    key_encryptsession(3) - interfaces to rpc keyserver daemon
    key_gendes(3) - interfaces to rpc keyserver daemon
    keymaps(5) - keyboard table descriptions for loadkeys and dumpkeys
    keyname(3x) - miscellaneous curses utility routines
    key_name(3x) - miscellaneous curses utility routines
    keyok(3x) - enable or disable a keycode
    keypad(3x) - curses input options
    keyrings(7) - in-kernel key management and retention facility
    key_secretkey_is_set(3) - interfaces to rpc keyserver daemon
    key_setsecret(3) - interfaces to rpc keyserver daemon
    keyutils(7) - in-kernel key management utilities
    kill(1) - terminate a process
    kill(1p) - terminate or signal processes
    kill(2) - send signal to a process
    kill(3p) - send a signal to a process or a group of processes
    killall(1) - kill processes by name
    killchar(3x) - curses environment query routines
    killpg(2) - send signal to a process group
    killpg(3) - send signal to a process group
    killpg(3p) - send a signal to a process group
    killwchar(3x) - curses environment query routines
    klogctl(3) - read and/or clear kernel message ring buffer; set console_loglevel
    kmem(4) - system memory, kernel memory and system ports
    kmod(8) - Program to manage Linux Kernel modules
    koi8-r(7) - Russian character set encoded in octal, decimal, and hexadecimal
    koi8-u(7) - Ukrainian character set encoded in octal, decimal, and hexadecimal

top
    l64a(3) - convert between long and base-64
    l64a(3p) - bit integer to a radix-64 ASCII string
    labs(3) - compute the absolute value of an integer
    labs(3p) - return a long integer absolute value
    langinfo.h(0p) - language information constants
    last(1) - list logins on the system
    lastb(1) - list logins on the system
    lastcomm(1) - print out information about previously executed commands.
    lastlog(8) - reports the most recent login of all users or of a given user
    latin1(7) - ISO 8859-1 character set encoded in octal, decimal, and hexadecimal
    latin10(7) - ISO 8859-16 character set encoded in octal, decimal, and hexadecimal
    latin2(7) - ISO 8859-2 character set encoded in octal, decimal, and hexadecimal
    latin3(7) - ISO 8859-3 character set encoded in octal, decimal, and hexadecimal
    latin4(7) - ISO 8859-4 character set encoded in octal, decimal, and hexadecimal
    latin5(7) - ISO 8859-9 character set encoded in octal, decimal, and hexadecimal
    latin6(7) - ISO 8859-10 character set encoded in octal, decimal, and hexadecimal
    latin7(7) - ISO 8859-13 character set encoded in octal, decimal, and hexadecimal
    latin8(7) - ISO 8859-14 character set encoded in octal, decimal, and hexadecimal
    latin9(7) - ISO 8859-15 character set encoded in octal, decimal, and hexadecimal
    lber-decode(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for decoding
    lber-encode(3) - OpenLDAP LBER simplified Basic Encoding Rules library routines for encoding
    lber-memory(3) - OpenLDAP LBER memory allocators
    lber-sockbuf(3) - OpenLDAP LBER I/O infrastructure
    lber-types(3) - OpenLDAP LBER types and allocation functions
    lchown(2) - change ownership of a file
    lchown(3p) - change the owner and group of a symbolic link
    lchown32(2) - change ownership of a file
    lckpwdf(3) - get shadow password file entry
    lcong48(3) - generate uniformly distributed pseudo-random numbers
    lcong48(3p) - random signed long integer generator
    lcong48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    ld-linux(8) - dynamic linker/loader
    ld-linux.so(8) - dynamic linker/loader
    ld(1) - The GNU linker
    ld.so(8) - dynamic linker/loader
    ldap(3) - OpenLDAP Lightweight Directory Access Protocol API
    ldap.conf(5) - LDAP configuration file/environment variables
    ldap_abandon(3) - Abandon an LDAP operation in progress
    ldap_abandon_ext(3) - Abandon an LDAP operation in progress
    ldapadd(1) - LDAP modify entry and LDAP add entry tools
    ldap_add(3) - Perform an LDAP add operation
    ldap_add_ext(3) - Perform an LDAP add operation
    ldap_add_ext_s(3) - Perform an LDAP add operation
    ldap_add_s(3) - Perform an LDAP add operation
    ldap_attributetype2name(3) - Schema definition handling routines
    ldap_attributetype2str(3) - Schema definition handling routines
    ldap_attributetype_free(3) - Schema definition handling routines
    ldap_bind(3) - LDAP bind routines
    ldap_bind_s(3) - LDAP bind routines
    ldapcompare(1) - LDAP compare tool
    ldap_compare(3) - Perform an LDAP compare operation.
    ldap_compare_ext(3) - Perform an LDAP compare operation.
    ldap_compare_ext_s(3) - Perform an LDAP compare operation.
    ldap_compare_s(3) - Perform an LDAP compare operation.
    ldap_control_create(3) - LDAP control manipulation routines
    ldap_control_dup(3) - LDAP control manipulation routines
    ldap_control_find(3) - LDAP control manipulation routines
    ldap_control_free(3) - LDAP control manipulation routines
    ldap_controls(3) - LDAP control manipulation routines
    ldap_controls_dup(3) - LDAP control manipulation routines
    ldap_controls_free(3) - LDAP control manipulation routines
    ldap_count_entries(3) - LDAP result entry parsing and counting routines
    ldap_count_messages(3) - Stepping through messages in a result chain
    ldap_count_references(3) - Stepping through continuation references in a result chain
    ldap_count_values(3) - LDAP attribute value handling routines
    ldap_count_values_len(3) - LDAP attribute value handling routines
    ldap_dcedn2dn(3) - LDAP DN handling routines
    ldapdelete(1) - LDAP delete entry tool
    ldap_delete(3) - Perform an LDAP delete operation.
    ldap_delete_ext(3) - Perform an LDAP delete operation.
    ldap_delete_ext_s(3) - Perform an LDAP delete operation.
    ldap_delete_s(3) - Perform an LDAP delete operation.
    ldap_destroy(3) - Duplicate and destroy LDAP session handles
    ldap_dn2ad_canonical(3) - LDAP DN handling routines
    ldap_dn2dcedn(3) - LDAP DN handling routines
    ldap_dn2str(3) - LDAP DN handling routines
    ldap_dn2ufn(3) - LDAP DN handling routines
    ldap_dnfree(3) - LDAP DN handling routines
    ldap_dup(3) - Duplicate and destroy LDAP session handles
    ldap_err2string(3) - LDAP protocol error handling routines
    ldap_errlist(3) - LDAP protocol error handling routines
    ldap_error(3) - LDAP protocol error handling routines
    ldapexop(1) - issue LDAP extended operations
    ldap_explode_dn(3) - LDAP DN handling routines
    ldap_explode_rdn(3) - LDAP DN handling routines
    ldap_extended_operation(3) - Extends the LDAP operations to the LDAP server.
    ldap_extended_operation_s(3) - Extends the LDAP operations to the LDAP server.
    ldap_first_attribute(3) - step through LDAP entry attributes
    ldap_first_entry(3) - LDAP result entry parsing and counting routines
    ldap_first_message(3) - Stepping through messages in a result chain
    ldap_first_reference(3) - Stepping through continuation references in a result chain
    ldap_free_urldesc(3) - LDAP Uniform Resource Locator routines
    ldap_get_dn(3) - LDAP DN handling routines
    ldap_get_option(3) - LDAP option handling routines
    ldap_get_values(3) - LDAP attribute value handling routines
    ldap_get_values_len(3) - LDAP attribute value handling routines
    ldap_init(3) - Initialize the LDAP library and open a connection to an LDAP server
    ldap_init_fd(3) - Initialize the LDAP library and open a connection to an LDAP server
    ldap_initialize(3) - Initialize the LDAP library and open a connection to an LDAP server
    ldap_install_tls(3) - LDAP TLS initialization routines
    ldap_is_ldap_url(3) - LDAP Uniform Resource Locator routines
    ldap_matchingrule2name(3) - Schema definition handling routines
    ldap_matchingrule2str(3) - Schema definition handling routines
    ldap_matchingrule_free(3) - Schema definition handling routines
    ldap_memalloc(3) - LDAP memory allocation routines
    ldap_memcalloc(3) - LDAP memory allocation routines
    ldap_memfree(3) - LDAP memory allocation routines
    ldap_memory(3) - LDAP memory allocation routines
    ldap_memrealloc(3) - LDAP memory allocation routines
    ldap_memvfree(3) - LDAP memory allocation routines
    ldapmodify(1) - LDAP modify entry and LDAP add entry tools
    ldap_modify(3) - Perform an LDAP modify operation
    ldap_modify_ext(3) - Perform an LDAP modify operation
    ldap_modify_ext_s(3) - Perform an LDAP modify operation
    ldap_modify_s(3) - Perform an LDAP modify operation
    ldapmodrdn(1) - LDAP rename entry tool
    ldap_modrdn(3) - Perform an LDAP modify RDN operation
    ldap_modrdn2(3) - Perform an LDAP modify RDN operation
    ldap_modrdn2_s(3) - Perform an LDAP modify RDN operation
    ldap_modrdn_s(3) - Perform an LDAP modify RDN operation
    ldap_mods_free(3) - Perform an LDAP modify operation
    ldap_msgfree(3) - Wait for the result of an LDAP operation
    ldap_msgid(3) - Wait for the result of an LDAP operation
    ldap_msgtype(3) - Wait for the result of an LDAP operation
    ldap_next_attribute(3) - step through LDAP entry attributes
    ldap_next_entry(3) - LDAP result entry parsing and counting routines
    ldap_next_message(3) - Stepping through messages in a result chain
    ldap_next_reference(3) - Stepping through continuation references in a result chain
    ldap_objectclass2name(3) - Schema definition handling routines
    ldap_objectclass2str(3) - Schema definition handling routines
    ldap_objectclass_free(3) - Schema definition handling routines
    ldap_open(3) - Initialize the LDAP library and open a connection to an LDAP server
    ldap_parse_extended_result(3) - Parsing results
    ldap_parse_reference(3) - Extract referrals and controls from a reference message
    ldap_parse_result(3) - Parsing results
    ldap_parse_sasl_bind_result(3) - Parsing results
    ldap_parse_sort_control(3) - Decode the information returned from a search operation that used a server-side sort control
    ldap_parse_vlv_control(3) - Decode the information returned from a search operation that used a VLV (virtual list view) control
    ldappasswd(1) - change the password of an LDAP entry
    ldap_perror(3) - LDAP protocol error handling routines
    ldap_rename(3) - Renames the specified entry.
    ldap_rename_s(3) - Renames the specified entry.
    ldap_result(3) - Wait for the result of an LDAP operation
    ldap_result2error(3) - LDAP protocol error handling routines
    ldap_sasl_bind(3) - LDAP bind routines
    ldap_sasl_bind_s(3) - LDAP bind routines
    ldap_sasl_interactive_bind_s(3) - LDAP bind routines
    ldap_schema(3) - Schema definition handling routines
    ldap_scherr2str(3) - Schema definition handling routines
    ldapsearch(1) - LDAP search tool
    ldap_search(3) - Perform an LDAP search operation
    ldap_search_ext(3) - Perform an LDAP search operation
    ldap_search_ext_s(3) - Perform an LDAP search operation
    ldap_search_s(3) - Perform an LDAP search operation
    ldap_search_st(3) - Perform an LDAP search operation
    ldap_set_option(3) - LDAP option handling routines
    ldap_set_rebind_proc(3) - LDAP bind routines
    ldap_set_urllist_proc(3) - Initialize the LDAP library and open a connection to an LDAP server
    ldap_simple_bind(3) - LDAP bind routines
    ldap_simple_bind_s(3) - LDAP bind routines
    ldap_sort(3) - LDAP sorting routines (deprecated)
    ldap_sort_entries(3) - LDAP sorting routines (deprecated)
    ldap_sort_strcasecmp(3) - LDAP sorting routines (deprecated)
    ldap_sort_values(3) - LDAP sorting routines (deprecated)
    ldap_start_tls(3) - LDAP TLS initialization routines
    ldap_start_tls_s(3) - LDAP TLS initialization routines
    ldap_str2attributetype(3) - Schema definition handling routines
    ldap_str2dn(3) - LDAP DN handling routines
    ldap_str2matchingrule(3) - Schema definition handling routines
    ldap_str2objectclass(3) - Schema definition handling routines
    ldap_str2syntax(3) - Schema definition handling routines
    ldap_strdup(3) - LDAP memory allocation routines
    ldap_sync(3) - LDAP sync routines
    ldap_sync_init(3) - LDAP sync routines
    ldap_sync_init_refresh_and_persist(3) - LDAP sync routines
    ldap_sync_init_refresh_only(3) - LDAP sync routines
    ldap_sync_poll(3) - LDAP sync routines
    ldap_syntax2name(3) - Schema definition handling routines
    ldap_syntax2str(3) - Schema definition handling routines
    ldap_syntax_free(3) - Schema definition handling routines
    ldap_tls(3) - LDAP TLS initialization routines
    ldap_tls_inplace(3) - LDAP TLS initialization routines
    ldap_unbind(3) - LDAP bind routines
    ldap_unbind_ext(3) - LDAP bind routines
    ldap_unbind_ext_s(3) - LDAP bind routines
    ldap_unbind_s(3) - LDAP bind routines
    ldapurl(1) - LDAP URL formatting tool
    ldap_url(3) - LDAP Uniform Resource Locator routines
    ldap_url_parse(3) - LDAP Uniform Resource Locator routines
    ldap_value_free(3) - LDAP attribute value handling routines
    ldap_value_free_len(3) - LDAP attribute value handling routines
    ldapwhoami(1) - LDAP who am i? tool
    ldattach(8) - attach a line discipline to a serial line
    ldconfig(8) - configure dynamic linker run-time bindings
    ldd(1) - print shared object dependencies
    ld_errno(3) - LDAP protocol error handling routines
    ldexp(3) - multiply floating-point number by integral power of 2
    ldexp(3p) - point number
    ldexpf(3) - multiply floating-point number by integral power of 2
    ldexpf(3p) - point number
    ldexpl(3) - multiply floating-point number by integral power of 2
    ldexpl(3p) - point number
    ldif(5) - LDAP Data Interchange Format
    ldiv(3) - compute quotient and remainder of an integer division
    ldiv(3p) - compute quotient and remainder of a long division
    le16toh(3) - convert values between host and big-/little-endian byte order
    le32toh(3) - convert values between host and big-/little-endian byte order
    le64toh(3) - convert values between host and big-/little-endian byte order
    leaveok(3x) - curses output options
    legacy_coding(3x) - override locale-encoding checks
    less(1) - opposite of more
    lessecho(1) - expand metacharacters
    lesskey(1) - specify key bindings for less
    lex(1p) - generate programs for lexical tasks (DEVELOPMENT)
    lexgrog(1) - parse header information in man pages
    lfind(3) - linear search of an array
    lfind(3p) - find entry in a linear search table
    lgamma(3) - log gamma function
    lgamma(3p) - log gamma function
    lgammaf(3) - log gamma function
    lgammaf(3p) - log gamma function
    lgammaf_r(3) - log gamma function
    lgammal(3) - log gamma function
    lgammal(3p) - log gamma function
    lgammal_r(3) - log gamma function
    lgamma_r(3) - log gamma function
    lgetfilecon(3) - get SELinux security context of a file
    lgetfilecon_raw(3) - get SELinux security context of a file
    lgetxattr(2) - retrieve an extended attribute value
    libabigail(7) - Library to analyze and compare ELF ABIs
    libaudit.conf(5) - libaudit configuration file
    libblkid(3) - block device identification library
    libc(7) - overview of standard C libraries on Linux
    libcap(3) - capability data object manipulation
    libexpect(3) - programmed dialogue library with interactive programs
    libgen.h(0p) - definitions for pattern matching functions
    libmagic(3) - Magic number recognition library
    libnetlink(3) - A library for accessing the netlink service
    libnss_myhostname.so.2(8) - Provide hostname resolution for the locally configured system hostname.
    libnss_mymachines.so.2(8) - Provide hostname resolution for local container instances.
    libnss_resolve.so.2(8) - Provide hostname resolution via systemd-resolved.service
    libnss_systemd.so.2(8) - Provide UNIX user and group name resolution for dynamic users and groups.
    libpfm(3) - a helper library to develop monitoring tools
    libpfm_amd64(3) - support for AMD64 processors
    libpfm_amd64_fam10h(3) - support for AMD64 Family 10h processors
    libpfm_amd64_fam15h(3) - support for AMD64 Family 15h processors
    libpfm_amd64_fam16h(3) - support for AMD64 Family 16h processors
    libpfm_amd64_fam17h(3) - support for AMD64 Family 17h processors
    libpfm_amd64_k7(3) - support for AMD64 K7 processors
    libpfm_amd64_k8(3) - support for AMD64 K8 processors
    libpfm_arm_ac15(3) - support for Arm Cortex A15 PMU
    libpfm_arm_ac53(3) - support for ARM Cortex A53 PMU
    libpfm_arm_ac57(3) - support for Arm Cortex A57 PMU
    libpfm_arm_ac7(3) - support for Arm Cortex A7 PMU
    libpfm_arm_ac8(3) - support for ARM Cortex A8 PMU
    libpfm_arm_ac9(3) - support for ARM Cortex A9 PMU
    libpfm_arm_qcom_krait(3) - support for Qualcomm Krait PMU
    libpfm_arm_xgene(3) - support for Applied Micro X-Gene PMU
    libpfm_intel_atom(3) - support for Intel Atom processors
    libpfm_intel_bdw(3) - support for Intel Broadwell core PMU
    libpfm_intel_bdx_unc_cbo(3) - support for Intel Broadwell Server C-Box uncore PMU
    libpfm_intel_bdx_unc_ha(3) - support for Intel Broadwell Server Home Agent (HA) uncore PMU
    libpfm_intel_bdx_unc_imc(3) - support for Intel Broadwell Server Integrated Memory Controller (IMC)  uncore PMU
    libpfm_intel_bdx_unc_irp(3) - support for Intel Broadwell Server IRP uncore PMU
    libpfm_intel_bdx_unc_pcu(3) - support for Intel Broadwell Server Power Controller Unit (PCU) uncore PMU
    libpfm_intel_bdx_unc_qpi(3) - support for Intel Broadwell Server  QPI uncore PMU
    libpfm_intel_bdx_unc_r2pcie(3) - support for Intel Broadwell Server R2 PCIe  uncore PMU
    libpfm_intel_bdx_unc_r3qpi(3) - support for Intel Broadwell Server R3QPI uncore PMU
    libpfm_intel_bdx_unc_sbo(3) - support for Intel Broadwell Server S-Box uncore PMU
    libpfm_intel_bdx_unc_ubo(3) - support for Intel Broadwell Server U-Box uncore PMU
    libpfm_intel_core(3) - support for Intel Core-based processors
    libpfm_intel_coreduo(3) - support for Intel Core Duo/Solo processors
    libpfm_intel_glm(3) - support for Intel Goldmont core PMU
    libpfm_intel_hsw(3) - support for Intel Haswell core PMU
    libpfm_intel_hswep_unc_cbo(3) - support for Intel Haswell-EP C-Box uncore PMU
    libpfm_intel_hswep_unc_ha(3) - support for Intel Haswell-EP Home Agent (HA) uncore PMU
    libpfm_intel_hswep_unc_imc(3) - support for Intel Haswell-EP Integrated Memory Controller (IMC)  uncore PMU
    libpfm_intel_hswep_unc_irp(3) - support for Intel Haswell-EP IRP uncore PMU
    libpfm_intel_hswep_unc_pcu(3) - support for Intel Haswell-EP Power Controller Unit (PCU) uncore PMU
    libpfm_intel_hswep_unc_qpi(3) - support for Intel Haswell-EP QPI uncore PMU
    libpfm_intel_hswep_unc_r2pcie(3) - support for Intel Haswell-EP R2 PCIe  uncore PMU
    libpfm_intel_hswep_unc_r3qpi(3) - support for Intel Haswell-EP R3QPI uncore PMU
    libpfm_intel_hswep_unc_sbo(3) - support for Intel Haswell-EP S-Box uncore PMU
    libpfm_intel_hswep_unc_ubo(3) - support for Intel Haswell-EP U-Box uncore PMU
    libpfm_intel_ivb(3) - support for Intel Ivy Bridge core PMU
    libpfm_intel_ivbep_unc_cbo(3) - support for Intel Ivy Bridge-EP C-Box uncore PMU
    libpfm_intel_ivbep_unc_ha(3) - support for Intel Ivy Bridge-EP Home Agent (HA) uncore PMU
    libpfm_intel_ivbep_unc_imc(3) - support for Intel Ivy Bridge-EP Integrated Memory Controller (IMC)  uncore PMU
    libpfm_intel_ivbep_unc_irp(3) - support for Intel Ivy Bridge-EP IRP uncore PMU
    libpfm_intel_ivbep_unc_pcu(3) - support for Intel Ivy Bridge-EP Power Controller Unit (PCU) uncore PMU
    libpfm_intel_ivbep_unc_qpi(3) - support for Intel Ivy Bridge-EP QPI uncore PMU
    libpfm_intel_ivbep_unc_r2pcie(3) - support for Intel Ivy Bridge-EP R2 PCIe  uncore PMU
    libpfm_intel_ivbep_unc_r3qpi(3) - support for Intel Ivy Bridge-EP R3QPI uncore PMU
    libpfm_intel_ivbep_unc_ubo(3) - support for Intel Ivy Bridge-EP U-Box uncore PMU
    libpfm_intel_ivb_unc(3) - support for Intel Ivy Bridge uncore PMU
    libpfm_intel_knc(3) - support for Intel Knights Corner
    libpfm_intel_knl(3) - support for Intel Kinghts Landing core PMU
    libpfm_intel_knm(3) - support for Intel Knights Mill core PMU
    libpfm_intel_nhm(3) - support for Intel Nehalem core PMU
    libpfm_intel_nhm_unc(3) -
    libpfm_intel_p6(3) - support for Intel P5 based processors
    libpfm_intel_rapl(3) - support for Intel RAPL PMU
    libpfm_intel_skl(3) - support for Intel SkyLake core PMU
    libpfm_intel_skx_unc_cha(3) - support for Intel Skylake X Server CHA-Box uncore PMU
    libpfm_intel_skx_unc_iio(3) - support for Intel Skylake X Server IIO uncore PMU
    libpfm_intel_skx_unc_imc(3) - support for Intel Skylake X Server Integrated Memory Controller (IMC)  uncore PMU
    libpfm_intel_skx_unc_irp(3) - support for Intel Broadwell Server IRP uncore PMU
    libpfm_intel_skx_unc_m2m(3) - support for Intel Skylake X Server M2M uncore PMU
    libpfm_intel_skx_unc_m3upi(3) - support for Intel Skylake X Server M3UPI uncore PMU
    libpfm_intel_skx_unc_pcu(3) - support for Intel Skylake X Power Controller Unit (PCU) uncore PMU
    libpfm_intel_skx_unc_ubo(3) - support for Intel Skylake X Server U-Box uncore PMU
    libpfm_intel_skx_unc_upi(3) - support for Intel Skylake X Server UPI uncore PMU
    libpfm_intel_slm(3) - support for Intel Silvermont core PMU
    libpfm_intel_snb(3) - support for Intel Sandy Bridge core PMU
    libpfm_intel_snbep_unc_cbo(3) - support for Intel Sandy Bridge-EP C-Box uncore PMU
    libpfm_intel_snbep_unc_ha(3) - support for Intel Sandy Bridge-EP Home Agent (HA) uncore PMU
    libpfm_intel_snbep_unc_imc(3) - support for Intel Sandy Bridge-EP Integrated Memory Controller (IMC)  uncore PMU
    libpfm_intel_snbep_unc_pcu(3) - support for Intel Sandy Bridge-EP Power Controller Unit (PCU) uncore PMU
    libpfm_intel_snbep_unc_qpi(3) - support for Intel Sandy Bridge-EP QPI uncore PMU
    libpfm_intel_snbep_unc_r2pcie(3) - support for Intel Sandy Bridge-EP R2 PCIe  uncore PMU
    libpfm_intel_snbep_unc_r3qpi(3) - support for Intel Sandy Bridge-EP R3QPI uncore PMU
    libpfm_intel_snbep_unc_ubo(3) - support for Intel Sandy Bridge-EP U-Box uncore PMU
    libpfm_intel_snb_unc(3) - support for Intel Sandy Bridge uncore PMU
    libpfm_intel_wsm(3) - support for Intel Westmere core PMU
    libpfm_intel_wsm_unc(3) -
    libpfm_intel_x86_arch(3) - support for Intel X86 architectural PMU
    libpfm_mips_74k(3) - support for MIPS 74k processors
    libpfm_perf_event_raw(3) - support for perf_events raw events syntax
    libpipeline(3) - pipeline manipulation library
    libudev(3) - API for enumerating and introspecting local devices
    limits.conf(5) - configuration file for the pam_limits module
    limits.h(0p) - defined constants
    line(1) - read one line
    LINES(3x) - curses global variables
    link(1) - call the link function to create a link to a file
    link(1p) - call link() function
    link(2) - make a new name for a file
    link(3p) - link one file to another file relative to two directory file descriptors
    linkat(2) - make a new name for a file
    linkat(3p) - link one file to another file relative to two directory file descriptors
    link_field(3x) - create and destroy form fields
    linux32(8) - change reported architecture in new program environment and/or set personality flags
    linux64(8) - change reported architecture in new program environment and/or set personality flags
    lio_listio(3) - initiate a list of I/O requests
    lio_listio(3p) - list directed I/O
    lirc(4) - lirc devices
    LIST_EMPTY(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_empty(3) - linked lists, singly-linked tail queues, lists and tail queues
    listen(2) - listen for connections on a socket
    listen(3p) - listen for socket connections and limit the queue of incoming connections
    LIST_ENTRY(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_entry(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_FIRST(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_first(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_FOREACH(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_foreach(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_HEAD_INITIALIZER(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_head_initializer(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_INIT(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_init(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_INSERT_AFTER(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_insert_after(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_INSERT_BEFORE(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_insert_before(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_INSERT_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_insert_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_NEXT(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_next(3) - linked lists, singly-linked tail queues, lists and tail queues
    LIST_REMOVE(3) - linked lists, singly-linked tail queues, lists and tail queues
    list_remove(3) - linked lists, singly-linked tail queues, lists and tail queues
    listxattr(2) - list extended attribute names
    lj4_font(5) - groff fonts for use with devlj4
    lkbib(1) - search bibliographic databases
    llabs(3) - compute the absolute value of an integer
    llabs(3p) - return a long integer absolute value
    lldiv(3) - compute quotient and remainder of an integer division
    lldiv(3p) - compute quotient and remainder of a long division
    llistxattr(2) - list extended attribute names
    llrint(3) - round to nearest integer
    llrint(3p) - round to the nearest integer value using current rounding direction
    llrintf(3) - round to nearest integer
    llrintf(3p) - round to the nearest integer value using current rounding direction
    llrintl(3) - round to nearest integer
    llrintl(3p) - round to the nearest integer value using current rounding direction
    llround(3) - round to nearest integer
    llround(3p) - round to nearest integer value
    llroundf(3) - round to nearest integer
    llroundf(3p) - round to nearest integer value
    llroundl(3) - round to nearest integer
    llroundl(3p) - round to nearest integer value
    llseek(2) - reposition read/write file offset
    _llseek(2) - reposition read/write file offset
    ln(1) - make links between files
    ln(1p) - link files
    lnstat(8) - unified linux network statistics
    loadkeys(1) - load keyboard translation tables
    load_policy(8) - load a new SELinux policy into the kernel
    loadunimap(8) - load the kernel unicode-to-font mapping table
    local.users(5) - The SELinux local users configuration file
    locale(1) - get locale-specific information
    locale(1p) - specific information
    locale(5) - describes a locale definition file
    locale(7) - description of multilanguage support
    locale.conf(5) - Configuration file for locale settings
    locale.h(0p) - category macros
    localeconv(3) - get numeric formatting information
    localeconv(3p) - specific information
    localectl(1) - Control the system locale and keyboard layout settings
    localedef(1) - compile locale definition files
    localedef(1p) - define locale environment
    localtime(3) - transform date and time to broken-down time or ASCII
    localtime(3p) - down local time
    localtime(5) - Local timezone configuration file
    localtime_r(3) - transform date and time to broken-down time or ASCII
    localtime_r(3p) - down local time
    locate(1) - list files in databases that match a pattern
    lock(2) - unimplemented system calls
    lockf(3) - apply, test or remove a POSIX lock on an open file
    lockf(3p) - record locking on files
    log(3) - natural logarithmic function
    log(3p) - natural logarithm function
    log10(3) - base-10 logarithmic function
    log10(3p) - base 10 logarithm function
    log10f(3) - base-10 logarithmic function
    log10f(3p) - base 10 logarithm function
    log10l(3) - base-10 logarithmic function
    log10l(3p) - base 10 logarithm function
    log1p(3) - logarithm of 1 plus argument
    log1p(3p) - compute a natural logarithm
    log1pf(3) - logarithm of 1 plus argument
    log1pf(3p) - compute a natural logarithm
    log1pl(3) - logarithm of 1 plus argument
    log1pl(3p) - compute a natural logarithm
    log2(3) - base-2 logarithmic function
    log2(3p) - compute base 2 logarithm functions
    log2f(3) - base-2 logarithmic function
    log2f(3p) - compute base 2 logarithm functions
    log2l(3) - base-2 logarithmic function
    log2l(3p) - compute base 2 logarithm functions
    LOGARCHIVE(5) - performance metrics archive format
    logarchive(5) - performance metrics archive format
    logb(3) - get exponent of a floating-point value
    logb(3p) - independent exponent
    logbf(3) - get exponent of a floating-point value
    logbf(3p) - independent exponent
    logbl(3) - get exponent of a floating-point value
    logbl(3p) - independent exponent
    logf(3) - natural logarithmic function
    logf(3p) - natural logarithm function
    logger(1) - enter messages into the system log
    logger(1p) - log messages
    LOGIMPORT(3) - introduction to the library for importing data and creating a PCP archive
    logimport(3) - introduction to the library for importing data and creating a PCP archive
    login(1) - begin session on the system
    login(3) - write utmp and wtmp entries
    login.defs(5) - shadow password suite configuration
    login.users(5) - Login file syntax for Firejail
    loginctl(1) - Control the systemd login manager
    logind.conf(5) - Login manager configuration files
    logind.conf.d(5) - Login manager configuration files
    login_tty(3) - terminal utility functions
    logl(3) - natural logarithmic function
    logl(3p) - natural logarithm function
    logname(1) - print user´s login name
    logname(1p) - return the user's login name
    logout(3) - write utmp and wtmp entries
    logoutd(8) - enforce login time restrictions
    logrotate(8) - logrotate ‐ rotates, compresses, and mails system logs
    logrotate.conf(5) - logrotate ‐ rotates, compresses, and mails system logs
    logsave(8) - save the output of a command in a logfile
    logwtmp(3) - append an entry to the wtmp file
    longjmp(3) - performing a nonlocal goto
    longjmp(3p) - local goto
    _longjmp(3p) - local goto
    longname(3x) - curses environment query routines
    look(1) - display lines beginning with a given string
    lookbib(1) - search bibliographic databases
    lookup_dcookie(2) - return a directory entry's path
    loop-control(4) - loop devices
    loop(4) - loop devices
    losetup(8) - set up and control loop devices
    lp(1) - print files
    lp(1p) - send files to a printer
    lp(4) - line printer devices
    lpadmin(8) - configure cups printers and classes
    lpc(8) - line printer control program
    lpinfo(8) - show available devices or drivers
    lpmove(8) - move a job or all jobs to a new destination
    lpoptions(1) - display or set printer options and defaults
    lpq(1) - show printer queue status
    lpr(1) - print files
    lprm(1) - cancel print jobs
    lpstat(1) - print cups status information
    lrand48(3) - generate uniformly distributed pseudo-random numbers
    lrand48(3p) - random non-negative long integers
    lrand48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    lremovexattr(2) - remove an extended attribute
    lrint(3) - round to nearest integer
    lrint(3p) - round to nearest integer value using current rounding direction
    lrintf(3) - round to nearest integer
    lrintf(3p) - round to nearest integer value using current rounding direction
    lrintl(3) - round to nearest integer
    lrintl(3p) - round to nearest integer value using current rounding direction
    lround(3) - round to nearest integer
    lround(3p) - round to nearest integer value
    lroundf(3) - round to nearest integer
    lroundf(3p) - round to nearest integer value
    lroundl(3) - round to nearest integer
    lroundl(3p) - round to nearest integer value
    ls(1) - list directory contents
    ls(1p) - list directory contents
    lsattr(1) - list file attributes on a Linux second extended file system
    lsblk(8) - list block devices
    lscpu(1) - display information about the CPU architecture
    lsearch(3) - linear search of an array
    lsearch(3p) - linear search and update
    lseek(2) - reposition read/write file offset
    lseek(3p) - move the read/write file offset
    lseek64(3) - reposition 64-bit read/write file offset
    lsetfilecon(3) - set SELinux security context of a file
    lsetfilecon_raw(3) - set SELinux security context of a file
    lsetxattr(2) - set an extended attribute value
    lsinitrd(1) - tool to show the contents of an initramfs image
    lsipc(1) - show information on IPC facilities currently employed in the system
    lslocks(8) - list local system locks
    lslogins(1) - display information about known users in the system
    lsmem(1) - list the ranges of available memory with their online status
    lsmod(8) - Show the status of modules in the Linux Kernel
    lsns(8) - list namespaces
    lsof(8) - list open files
    lspci(8) - list all PCI devices
    lstat(2) - get file status
    lstat(3p) - get file status
    lstat64(2) - get file status
    lsusb(8) - list USB devices
    ltrace(1) - A library call tracer
    ltrace.conf(5) - Configuration file for ltrace(1).
    lttng-add-context(1) - Add context fields to an LTTng channel
    lttng-calibrate(1) - Quantify LTTng overhead
    lttng-crash(1) - Recover and view LTTng 2 trace buffers in the event of a crash
    lttng-create(1) - Create an LTTng tracing session
    lttng-destroy(1) - Destroy an LTTng tracing session
    lttng-disable-channel(1) - Disable LTTng channels
    lttng-disable-event(1) - Disable LTTng event rules
    lttng-disable-rotation(1) - Unset a tracing session's rotation schedule
    lttng-enable-channel(1) - Create or enable LTTng channels
    lttng-enable-event(1) - Create or enable LTTng event rules
    lttng-enable-rotation(1) - Set a tracing session's rotation schedule
    lttng-gen-tp(1) - Generate LTTng-UST tracepoint provider code
    lttng-health-check(3) - DEPRECATED
    lttng-help(1) - Display help information about an LTTng command
    lttng-list(1) - List LTTng tracing sessions, domains, channels, and events
    lttng-load(1) - Load LTTng tracing session configurations
    lttng-metadata(1) - Manage an LTTng tracing session's metadata generation
    lttng-regenerate(1) - Manage an LTTng tracing session's data regeneration
    lttng-relayd(8) - LTTng 2 relay daemon
    lttng-rotate(1) - Archive a tracing session's current trace chunk
    lttng-save(1) - Save LTTng tracing session configurations
    lttng-sessiond(8) - LTTng 2 tracing session daemon
    lttng-set-session(1) - Set the current LTTng tracing session
    lttng-snapshot(1) - Take LTTng snapshots and configure snapshot outputs
    lttng-start(1) - Start LTTng tracers
    lttng-status(1) - Get the current LTTng tracing session's status
    lttng-stop(1) - Stop LTTng tracers
    lttng-track(1) - Add one or more entries to an LTTng resource tracker
    lttng-untrack(1) - Remove one or more entries from an LTTng resource tracker
    lttng-ust-cyg-profile(3) - Function tracing (LTTng-UST helper)
    lttng-ust-dl(3) - Dynamic linker tracing (LTTng-UST helper)
    lttng-ust(3) - LTTng user space tracing
    lttng-version(1) - Get the version of LTTng-tools
    lttng-view(1) - View the traces of an LTTng tracing session
    lttng(1) - LTTng 2 tracer control command-line tool
    lttng_health_check(3) - DEPRECATED
    lttngtop(1) - LTTng Trace Viewer
    lttngtoptrace(1) - Live textual LTTng Trace Viewer
    lutimes(3) - change file timestamps
    lvchange(8) - Change the attributes of logical volume(s)
    lvconvert(8) - Change logical volume layout
    lvcreate(8) - Create a logical volume
    lvdisplay(8) - Display information about a logical volume
    lvextend(8) - Add space to a logical volume
    lvm-config(8) - Display and manipulate configuration information
    lvm-dumpconfig(8) - Display and manipulate configuration information
    lvm-fullreport(8) - Display full report
    lvm-lvpoll(8) - Continue already initiated poll operation on a logical volume
    lvm(8) - LVM2 tools
    lvm.conf(5) - Configuration file for LVM2
    lvm2-activation-generator(8) - generator for systemd units to activate LVM2 volumes on boot
    lvmcache(7) - LVM caching
    lvmconfig(8) - Display and manipulate configuration information
    lvmdbusd(8) - Bus daemon
    lvmdiskscan(8) - List devices that may be used as physical volumes
    lvmdump(8) - create lvm2 information dumps for diagnostic purposes
    lvmetad(8) - LVM metadata cache daemon
    lvmlockctl(8) - Control for lvmlockd
    lvmlockd(8) - LVM locking daemon
    lvmpolld(8) - LVM poll daemon
    lvmraid(7) - LVM RAID
    lvmreport(7) - LVM reporting and related features
    lvmsadc(8) - LVM system activity data collector
    lvmsar(8) - LVM system activity reporter
    lvmsystemid(7) - LVM system ID
    lvmthin(7) - LVM thin provisioning
    lvpoll(8) - Continue already initiated poll operation on a logical volume
    lvreduce(8) - Reduce the size of a logical volume
    lvremove(8) - Remove logical volume(s) from the system
    lvrename(8) - Rename a logical volume
    lvresize(8) - Resize a logical volume
    lvs(8) - Display information about logical volumes
    lvscan(8) - List all logical volumes in all volume groups
    lxc-attach(1) - start a process inside a running container.
    lxc-autostart(1) - start/stop/kill auto-started containers
    lxc-cgroup(1) - manage the control group associated with a container
    lxc-checkconfig(1) - check the current kernel for lxc support
    lxc-checkpoint(1) - checkpoint a container
    lxc-config(1) - query LXC system configuration
    lxc-console(1) - Launch a console for the specified container
    lxc-copy(1) - copy an existing container.
    lxc-create(1) - creates a container
    lxc-destroy(1) - destroy a container.
    lxc-device(1) - manage devices of running containers
    lxc-execute(1) - run an application inside a container.
    lxc-freeze(1) - freeze all the container's processes
    lxc-info(1) - query information about a container
    lxc-ls(1) - list the containers existing on the system
    lxc-monitor(1) - monitor the container state
    lxc-snapshot(1) - Snapshot an existing container.
    lxc-start(1) - run an application inside a container.
    lxc-stop(1) - stop the application running inside a container
    lxc-top(1) - monitor container statistics
    lxc-unfreeze(1) - thaw all the container's processes
    lxc-unshare(1) - Run a task in a new set of namespaces.
    lxc-update-config(1) - update a legacy pre LXC 2.1 configuration file
    lxc-user-nic(1) - Create and attach a nic to another network namespace.
    lxc-usernet(5) - unprivileged user network administration file.
    lxc-usernsexec(1) - Run a task as root in a new user namespace.
    lxc-wait(1) - wait for a specific container state
    lxc(7) - linux containers
    lxc.conf(5) - Configuration files for LXC.
    lxc.container.conf(5) - LXC container configuration file
    lxc.system.conf(5) - LXC system configuration file

top
    m4(1p) - macro processor
    machine-id(5) - Local machine ID configuration file
    machine-info(5) - Local machine information file
    machinectl(1) - Control the systemd machine manager
    madvise(2) - give advice about use of memory
    madvise1(2) - unimplemented system calls
    magic(4) - file command's magic pattern file
    magic_buffer(3) - Magic number recognition library
    magic_check(3) - Magic number recognition library
    magic_close(3) - Magic number recognition library
    magic_compile(3) - Magic number recognition library
    magic_descriptor(3) - Magic number recognition library
    magic_errno(3) - Magic number recognition library
    magic_error(3) - Magic number recognition library
    magic_getflags(3) - Magic number recognition library
    magic_getparam(3) - Magic number recognition library
    magic_list(3) - Magic number recognition library
    magic_load(3) - Magic number recognition library
    magic_load_buffers(3) - Magic number recognition library
    magic_open(3) - Magic number recognition library
    magic_setflags(3) - Magic number recognition library
    magic_setparam(3) - Magic number recognition library
    magic_version(3) - Magic number recognition library
    mailaddr(7) - mail addressing description
    mailto.conf(5) - configuration file for cups email notifier
    mailx(1p) - process messages
    major(3) - manage a device number
    make(1) - GNU make utility to maintain groups of programs
    make(1p) - maintain, update, and regenerate groups of programs (DEVELOPMENT)
    makecontext(3) - manipulate user context
    makedev(3) - manage a device number
    make_win_bin_dist(1) - package MySQL distribution as ZIP archive
    mallinfo(3) - obtain memory allocation information
    malloc(3) - allocate and free dynamic memory
    malloc(3p) - a memory allocator
    malloc_get_state(3) - record and restore state of malloc implementation
    malloc_hook(3) - malloc debugging variables
    __malloc_hook(3) - malloc debugging variables
    malloc_info(3) - export malloc state to a stream
    __malloc_initialize_hook(3) - malloc debugging variables
    malloc_set_state(3) - record and restore state of malloc implementation
    malloc_stats(3) - print memory allocation statistics
    malloc_trim(3) - release free memory from the top of the heap
    malloc_usable_size(3) - obtain size of block of memory allocated from heap
    mallopt(3) - set memory allocation parameters
    man-pages(7) - conventions for writing Linux man pages
    man(1) - an interface to the on-line reference manuals
    man(1p) - display system documentation
    man(7) - macros to format man pages
    manconv(1) - convert manual page from one encoding to another
    mandb(8) - create or update the manual page index caches
    manpath(1) - determine search path for manual pages
    manpath(5) - format of the /usr/local/etc/man_db.conf file
    manual_user_enter_context(3) - determine SELinux context(s) for user sessions
    mapscrn(8) - load screen output mapping table
    mariabackup(1) - Backup tool
    mariadb-service-convert(1) - generate a mariadb.service file based on the current mysql/mariadb settings
    matchall(8) - traffic control filter that matches every packet
    matchmediacon(3) - get the default SELinux security context for the specified mediatype from the policy
    matchpathcon(3) - get the default SELinux security context for the specified path from the file contexts configuration
    matchpathcon(8) - get the default SELinux security context for the specified path from the file contexts configuration
    matchpathcon_checkmatches(3) - check and report whether any specification index has no matches with any inode. Maintenance and statistics on inode associations
    matchpathcon_filespec_add(3) - check and report whether any specification index has no matches with any inode. Maintenance and statistics on inode associations
    matchpathcon_filespec_destroy(3) - check and report whether any specification index has no matches with any inode. Maintenance and statistics on inode associations
    matchpathcon_filespec_eval(3) - check and report whether any specification index has no matches with any inode. Maintenance and statistics on inode associations
    matchpathcon_fini(3) - get the default SELinux security context for the specified path from the file contexts configuration
    matchpathcon_index(3) - get the default SELinux security context for the specified path from the file contexts configuration
    matchpathcon_init(3) - get the default SELinux security context for the specified path from the file contexts configuration
    math.h(0p) - mathematical declarations
    matherr(3) - SVID math library exception handling
    math_error(7) - detecting errors from mathematical functions
    mausezahn(8) - a fast versatile packet generator with Cisco-cli
    MB_CUR_MAX(3) - maximum length of a multibyte character in the current locale
    mb_cur_max(3) - maximum length of a multibyte character in the current locale
    mbind(2) - set memory policy for a memory range
    mblen(3) - determine number of bytes in next multibyte character
    mblen(3p) - get number of bytes in a character
    MB_LEN_MAX(3) - maximum multibyte length of a character across all locales
    mb_len_max(3) - maximum multibyte length of a character across all locales
    mbrlen(3) - determine number of bytes in next multibyte character
    mbrlen(3p) - get number of bytes in a character (restartable)
    mbrtowc(3) - convert a multibyte sequence to a wide character
    mbrtowc(3p) - character code (restartable)
    mbsinit(3) - test for initial shift state
    mbsinit(3p) - determine conversion object status
    mbsnrtowcs(3) - convert a multibyte string to a wide-character string
    mbsnrtowcs(3p) - character string (restartable)
    mbsrtowcs(3) - convert a multibyte string to a wide-character string
    mbsrtowcs(3p) - character string (restartable)
    mbstowcs(3) - convert a multibyte string to a wide-character string
    mbstowcs(3p) - character string
    mbstream(1) - Serialize/deserialize files in the XBSTREAM format
    mbtowc(3) - convert a multibyte sequence to a wide character
    mbtowc(3p) - character code
    mcheck(3) - heap consistency checking
    mcheck_check_all(3) - heap consistency checking
    mcheck_pedantic(3) - heap consistency checking
    mckey(1) - RDMA CM multicast setup and simple data transfer test.
    mcookie(1) - generate magic cookies for xauth
    mcprint(3x) - ship binary data to printer
    mcs(8) - Multi-Category System
    mcstransd(8) - MCS (Multiple Category System) daemon.  Translates SELinux MCS/MLS labels to human readable form.
    md(4) - Multiple Device driver aka Linux Software RAID
    md5sum(1) - compute and check MD5 message digest
    mdadm(8) - manage MD devices aka Linux Software RAID
    mdadm.conf(5) - configuration for management of Software RAID with mdadm
    mdmon(8) - monitor MD external metadata arrays
    mdoc(7) - mdoc macro package
    mdoc.samples(7) - mdoc
    media(5) - userspace SELinux labeling interface and configuration file format for the media contexts backend
    mem(4) - system memory, kernel memory and system ports
    memalign(3) - allocate aligned memory
    __memalign_hook(3) - malloc debugging variables
    membarrier(2) - issue memory barriers on a set of threads
    memccpy(3) - copy memory area
    memccpy(3p) - copy bytes in memory
    memchr(3) - scan memory for a character
    memchr(3p) - find byte in memory
    memcmp(3) - compare memory areas
    memcmp(3p) - compare bytes in memory
    memcpy(3) - copy memory area
    memcpy(3p) - copy bytes in memory
    memfd_create(2) - create an anonymous file
    memfrob(3) - frobnicate (encrypt) a memory area
    memmem(3) - locate a substring
    memmove(3) - copy memory area
    memmove(3p) - copy bytes in memory with overlapping areas
    mempcpy(3) - copy memory area
    memrchr(3) - scan memory for a character
    memset(3) - fill memory with a constant byte
    memset(3p) - set bytes in memory
    memusage(1) - profile memory usage of a program
    memusagestat(1) - generate graphic from memory profiling data
    menu(3x) - curses extension for programming menus
    menu_attributes(3x) - color and attribute control for menus
    menu_back(3x) - color and attribute control for menus
    menu_cursor(3x) - position a menu's cursor
    menu_driver(3x) - command-processing loop of the menu system
    menu_fore(3x) - color and attribute control for menus
    menu_format(3x) - set and get menu sizes
    menu_grey(3x) - color and attribute control for menus
    menu_hook(3x) - set hooks for automatic invocation by applications
    menu_items(3x) - make and break connections between items and menus
    menu_mark(3x) - get and set the menu mark string
    menu_new(3x) - create and destroy menus
    menu_opts(3x) - set and get menu options
    menu_opts_off(3x) - set and get menu options
    menu_opts_on(3x) - set and get menu options
    menu_pad(3x) - color and attribute control for menus
    menu_pattern(3x) - set and get a menu's pattern buffer
    menu_post(3x) - write or erase menus from associated subwindows
    menu_request_by_name(3x) - handle printable menu request names
    menu_requestname(3x) - handle printable menu request names
    menu_request_name(3x) - handle printable menu request names
    menu_spacing(3x) - set and get spacing between menu items.
    menu_userptr(3x) - associate application data with a menu item
    menu_win(3x) - make and break menu window and subwindow associations
    mesg(1) - display (or do not display) messages from other users
    mesg(1p) - permit or deny messages
    meta(3x) - curses input options
    migrate_pages(2) - move all pages in a process to another set of nodes
    migratepages(8) - Migrate the physical location a processes pages
    migspeed(8) - Test the speed of page migration
    mii-tool(8) - view, manipulate media-independent interface status
    mime.convs(5) - mime type conversion file for cups
    mime.types(5) - mime type description file for cups
    mincore(2) - determine whether pages are resident in memory
    miniunzip(1) - uncompress and examine ZIP archives
    minizip(1) - create ZIP archives
    minor(3) - manage a device number
    mirred(8) - mirror/redirect action
    misc_conv(3) - text based conversation function
    mitem_current(3x) - set and get current_menu_item
    mitem_name(3x) - get menu item name and description fields
    mitem_new(3x) - create and destroy menu items
    mitem_opts(3x) - set and get menu item options
    mitem_userptr(3x) - associate application data with a menu item
    mitem_value(3x) - set and get menu item values
    mitem_visible(3x) - check visibility of a menu item
    mkaf(1) - create a Performance Co-Pilot archive folio
    mkdir(1) - make directories
    mkdir(1p) - make directories
    mkdir(2) - create a directory
    mkdir(3p) - make a directory relative to directory file descriptor
    mkdirat(2) - create a directory
    mkdirat(3p) - make a directory relative to directory file descriptor
    mkdtemp(3) - create a unique temporary directory
    mkdtemp(3p) - create a unique directory or file
    mke2fs(8) - create an ext2/ext3/ext4 filesystem
    mke2fs.conf(5) - Configuration file for mke2fs
    mkfifo(1) - make FIFOs (named pipes)
    mkfifo(1p) - make FIFO special files
    mkfifo(3) - make a FIFO special file (a named pipe)
    mkfifo(3p) - make a FIFO special file relative to directory file descriptor
    mkfifoat(3) - make a FIFO special file (a named pipe)
    mkfifoat(3p) - make a FIFO special file relative to directory file descriptor
    mkfs(8) - build a Linux filesystem
    mkfs.bfs(8) - make an SCO bfs filesystem
    mkfs.btrfs(8) - create a btrfs filesystem
    mkfs.cramfs(8) - make compressed ROM file system
    mkfs.minix(8) - make a Minix filesystem
    mkfs.xfs(8) - construct an XFS filesystem
    mkhomedir_helper(8) - Helper binary that creates home directories
    mkinitrd-suse(8) - is a compat wrapper, which calls dracut to generate an initramfs
    mkinitrd(8) - is a compat wrapper, which calls dracut to generate an initramfs
    mklost+found(8) - create a lost+found directory on a mounted Linux second extended file system
    mknod(1) - make block or character special files
    mknod(2) - create a special or ordinary file
    mknod(3p) - make directory, special file, or regular file
    mknodat(2) - create a special or ordinary file
    mknodat(3p) - make directory, special file, or regular file
    mkostemp(3) - create a unique temporary file
    mkostemps(3) - create a unique temporary file
    mkstemp(3) - create a unique temporary file
    mkstemp(3p) - create a unique directory
    mkstemps(3) - create a unique temporary file
    mkswap(8) - set up a Linux swap area
    mktemp(1) - create a temporary file or directory
    mktemp(3) - make a unique temporary filename
    mktime(3) - transform date and time to broken-down time or ASCII
    mktime(3p) - down time into time since the Epoch
    mlock(2) - lock and unlock memory
    mlock(3p) - lock or unlock a range of process address space (REALTIME)
    mlock2(2) - lock and unlock memory
    mlockall(2) - lock and unlock memory
    mlockall(3p) - lock/unlock the address space of a process (REALTIME)
    mlx4dv(7) - Direct verbs for mlx4 devices
    mlx4dv_init_obj(3) - Initialize mlx4 direct verbs object from ibv_xxx structures
    mlx4dv_query_device(3) - Query device capabilities specific to mlx4
    mlx5dv(7) - Direct verbs for mlx5 devices
    mlx5dv_get_clock_info(3) - Get device clock information
    mlx5dv_init_obj(3) - Initialize mlx5 direct verbs object from ibv_xxx structures
    mlx5dv_query_device(3) - Query device capabilities specific to mlx5
    mlx5dv_ts_to_ns(3) - Convert device timestamp from HCA core clock units to the corresponding nanosecond counts
    mmap(2) - map or unmap files or devices into memory
    mmap(3p) - map pages of memory
    mmap2(2) - map files or devices into memory
    mmap64(3) - map or unmap files or devices into memory
    mmroff(1) - cross-reference preprocessor for GNU roff mm macro package
    mmv(5) - Memory Mapped Values for Performance Co-Pilot
    mmv_inc_value(3) - update a value in a Memory Mapped Value file
    mmv_lookup_value_desc(3) - find a value in the Memory Mapped Value file
    mmv_stats2_init(3) - create and initialize Memory Mapped Value file
    mmv_stats_init(3) - create and initialize Memory Mapped Value file
    mmv_stats_registry(3) - Initialize the Memory Mapped Value file
    mode_to_security_class(3) - display an access vector in human-readable form.
    modf(3) - extract signed integral and fractional values from floating-point number
    modf(3p) - point number
    modff(3) - extract signed integral and fractional values from floating-point number
    modff(3p) - point number
    modfl(3) - extract signed integral and fractional values from floating-point number
    modfl(3p) - point number
    modify_ldt(2) - get or set a per-process LDT entry
    modinfo(8) - Show information about a Linux Kernel module
    modprobe(8) - Add and remove modules from the Linux Kernel
    modprobe.d(5) - Configuration directory for modprobe
    modules-load.d(5) - Configure kernel modules to load at boot
    modules.dep(5) - Module dependency information
    modules.dep.bin(5) - Module dependency information
    moduli(5) - Hellman moduli
    monetary.h(0p) - monetary types
    more(1) - file perusal filter for crt viewing
    more(1p) - by-page basis
    motd(5) - message of the day
    mount(2) - mount filesystem
    mount(8) - mount a filesystem
    mount.fuse3(8) - configuration and mount options for FUSE file systems
    mount.nfs(8) - mount a Network File System
    mount.nfs4(8) - mount a Network File System
    mountd(8) - NFS mount daemon
    mount_namespaces(7) - overview of Linux mount namespaces
    mountpoint(1) - see if a directory or file is a mountpoint
    mountstats(8) - Displays various NFS client per-mount statistics
    mouse(4) - serial mouse interface
    mouseinterval(3x) - mouse interface through curses
    mousemask(3x) - mouse interface through curses
    mouse_trafo(3x) - mouse interface through curses
    move(3x) - move curses window cursor
    move_pages(2) - move individual pages of a process to another node
    mpool(3) - shared memory buffer pool
    mprobe(3) - heap consistency checking
    mprotect(2) - set protection on a region of memory
    mprotect(3p) - set protection of memory mapping
    mpstat(1) - Report processors related statistics.
    mpx(2) - unimplemented system calls
    mq_close(3) - close a message queue descriptor
    mq_close(3p) - close a message queue (REALTIME)
    mq_getattr(3) - get/set message queue attributes
    mq_getattr(3p) - get message queue attributes (REALTIME)
    mq_getsetattr(2) - get/set message queue attributes
    mq_notify(2) - register for notification when a message is available
    mq_notify(3) - register for notification when a message is available
    mq_notify(3p) - notify process that a message is available (REALTIME)
    mq_open(2) - open a message queue
    mq_open(3) - open a message queue
    mq_open(3p) - open a message queue (REALTIME)
    mq_overview(7) - overview of POSIX message queues
    MQPRIO(8) - Multiqueue Priority Qdisc (Offloaded Hardware QOS)
    mq_receive(3) - receive a message from a message queue
    mq_receive(3p) - receive a message from a message queue (REALTIME)
    mq_send(3) - send a message to a message queue
    mq_send(3p) - send a message to a message queue (REALTIME)
    mq_setattr(3) - get/set message queue attributes
    mq_setattr(3p) - set message queue attributes (REALTIME)
    mq_timedreceive(2) - receive a message from a message queue
    mq_timedreceive(3) - receive a message from a message queue
    mq_timedreceive(3p) - receive a message from a message queue (ADVANCED REALTIME)
    mq_timedsend(2) - send a message to a message queue
    mq_timedsend(3) - send a message to a message queue
    mq_timedsend(3p) - send a message to a message queue (ADVANCED REALTIME)
    mqueue.h(0p) - message queues (REALTIME)
    mq_unlink(2) - remove a message queue
    mq_unlink(3) - remove a message queue
    mq_unlink(3p) - remove a message queue (REALTIME)
    mrand48(3) - generate uniformly distributed pseudo-random numbers
    mrand48(3p) - random signed long integers
    mrand48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    mremap(2) - remap a virtual memory address
    mrtg2pcp(1) - import MRTG data and create a PCP archive
    msgattrib(1) - attribute matching and manipulation on message catalog
    msgcat(1) - combines several message catalogs
    msgcmp(1) - compare message catalog and template
    msgcomm(1) - match two message catalogs
    msgconv(1) - character set conversion for message catalog
    msgctl(2) - System V message control operations
    msgctl(3p) - XSI message control operations
    msgen(1) - create English message catalog
    msgexec(1) - process translations of message catalog
    msgfilter(1) - edit translations of message catalog
    msgfmt(1) - compile message catalog to binary format
    msgget(2) - get a System V message queue identifier
    msgget(3p) - get the XSI message queue identifier
    msggrep(1) - pattern matching on message catalog
    msginit(1) - initialize a message catalog
    msgmerge(1) - merge message catalog and template
    msgop(2) - System V message queue operations
    msgrcv(2) - System V message queue operations
    msgrcv(3p) - XSI message receive operation
    msgsnd(2) - System V message queue operations
    msgsnd(3p) - XSI message send operation
    msgunfmt(1) - uncompile message catalog from binary format
    msguniq(1) - unify duplicate translations in message catalog
    ms_print(1) - post-processing tool for Massif
    msql2mysql(1) - convert mSQL programs for use with MySQL
    msr(4) - x86 CPU MSR access device
    msync(2) - synchronize a file with a memory map
    msync(3p) - synchronize memory with physical storage
    mtrace(1) - interpret the malloc trace log
    mtrace(3) - malloc tracing
    munlock(2) - lock and unlock memory
    munlock(3p) - unlock a range of process address space
    munlockall(2) - lock and unlock memory
    munlockall(3p) - unlock the address space of a process
    munmap(2) - map or unmap files or devices into memory
    munmap(3p) - unmap pages of memory
    muntrace(3) - malloc tracing
    mv(1) - move (rename) files
    mv(1p) - move files
    mvaddch(3x) - add a character (with attributes) to a curses window, then advance the cursor
    mvaddchnstr(3x) - add a string of characters (and attributes) to a curses window
    mvaddchstr(3x) - add a string of characters (and attributes) to a curses window
    mvaddnstr(3x) - add a string of characters to a curses window and advance cursor
    mvaddnwstr(3x) - add a string of wide characters to a curses window and advance cursor
    mvaddstr(3x) - add a string of characters to a curses window and advance cursor
    mvadd_wch(3x) - add a complex character and rendition to a curses window, then advance the cursor
    mvadd_wchnstr(3x) - add an array of complex characters (and attributes) to a curses window
    mvadd_wchstr(3x) - add an array of complex characters (and attributes) to a curses window
    mvaddwstr(3x) - add a string of wide characters to a curses window and advance cursor
    mvchgat(3x) - curses character and window attribute control routines
    mvcur(3x) - curses interfaces to terminfo database
    mvdelch(3x) - delete character under the cursor in a curses window
    mvderwin(3x) - create curses windows
    mvgetch(3x) - get (or push back) characters from curses terminal keyboard
    mvgetnstr(3x) - accept character strings from curses terminal keyboard
    mvgetn_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    mvgetstr(3x) - accept character strings from curses terminal keyboard
    mvget_wch(3x) - get (or push back) a wide character from curses terminal keyboard
    mvget_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    mvhline(3x) - create curses borders, horizontal and vertical lines
    mvhline_set(3x) - create curses borders or lines using complex characters and renditions
    mvinch(3x) - get a character and attributes from a curses window
    mvinchnstr(3x) - get a string of characters (and attributes) from a curses window
    mvinchstr(3x) - get a string of characters (and attributes) from a curses window
    mvinnstr(3x) - get a string of characters from a curses window
    mvinnwstr(3x) - get a string of wchar_t characters from a curses window
    mvinsch(3x) - insert a character before cursor in a curses window
    mvinsnstr(3x) - insert string before cursor in a curses window
    mvins_nwstr(3x) - insert a wide-character string into a curses window
    mvinsstr(3x) - insert string before cursor in a curses window
    mvinstr(3x) - get a string of characters from a curses window
    mvins_wch(3x) - insert a complex character and rendition into a window
    mvins_wstr(3x) - insert a wide-character string into a curses window
    mvin_wch(3x) - extract a complex character and rendition from a window
    mvin_wchnstr(3x) - get an array of complex characters and renditions from a curses window
    mvin_wchstr(3x) - get an array of complex characters and renditions from a curses window
    mvinwstr(3x) - get a string of wchar_t characters from a curses window
    mvprintw(3x) - print formatted output in curses windows
    mvscanw(3x) - convert formatted input from a curses window
    mvvline(3x) - create curses borders, horizontal and vertical lines
    mvvline_set(3x) - create curses borders or lines using complex characters and renditions
    mvwaddch(3x) - add a character (with attributes) to a curses window, then advance the cursor
    mvwaddchnstr(3x) - add a string of characters (and attributes) to a curses window
    mvwaddchstr(3x) - add a string of characters (and attributes) to a curses window
    mvwaddnstr(3x) - add a string of characters to a curses window and advance cursor
    mvwaddnwstr(3x) - add a string of wide characters to a curses window and advance cursor
    mvwaddstr(3x) - add a string of characters to a curses window and advance cursor
    mvwadd_wch(3x) - add a complex character and rendition to a curses window, then advance the cursor
    mvwadd_wchnstr(3x) - add an array of complex characters (and attributes) to a curses window
    mvwadd_wchstr(3x) - add an array of complex characters (and attributes) to a curses window
    mvwaddwstr(3x) - add a string of wide characters to a curses window and advance cursor
    mvwchgat(3x) - curses character and window attribute control routines
    mvwdelch(3x) - delete character under the cursor in a curses window
    mvwgetch(3x) - get (or push back) characters from curses terminal keyboard
    mvwgetnstr(3x) - accept character strings from curses terminal keyboard
    mvwgetn_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    mvwgetstr(3x) - accept character strings from curses terminal keyboard
    mvwget_wch(3x) - get (or push back) a wide character from curses terminal keyboard
    mvwget_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    mvwhline(3x) - create curses borders, horizontal and vertical lines
    mvwhline_set(3x) - create curses borders or lines using complex characters and renditions
    mvwin(3x) - create curses windows
    mvwinch(3x) - get a character and attributes from a curses window
    mvwinchnstr(3x) - get a string of characters (and attributes) from a curses window
    mvwinchstr(3x) - get a string of characters (and attributes) from a curses window
    mvwinnstr(3x) - get a string of characters from a curses window
    mvwinnwstr(3x) - get a string of wchar_t characters from a curses window
    mvwinsch(3x) - insert a character before cursor in a curses window
    mvwinsnstr(3x) - insert string before cursor in a curses window
    mvwins_nwstr(3x) - insert a wide-character string into a curses window
    mvwinsstr(3x) - insert string before cursor in a curses window
    mvwinstr(3x) - get a string of characters from a curses window
    mvwins_wch(3x) - insert a complex character and rendition into a window
    mvwins_wstr(3x) - insert a wide-character string into a curses window
    mvwin_wch(3x) - extract a complex character and rendition from a window
    mvwin_wchnstr(3x) - get an array of complex characters and renditions from a curses window
    mvwin_wchstr(3x) - get an array of complex characters and renditions from a curses window
    mvwinwstr(3x) - get a string of wchar_t characters from a curses window
    mvwprintw(3x) - print formatted output in curses windows
    mvwscanw(3x) - convert formatted input from a curses window
    mvwvline(3x) - create curses borders, horizontal and vertical lines
    mvwvline_set(3x) - create curses borders or lines using complex characters and renditions
    myisamchk(1) - MyISAM table-maintenance utility
    myisam_ftdump(1) - display full-text index information
    myisamlog(1) - display MyISAM log file contents
    myisampack(1) - generate compressed, read-only MyISAM tables
    my_print_defaults(1) - display options from option files
    my_safe_process(1) - Utility program that encapsulates process creation, monitoring and bulletproof process cleanup
    mysql-stress-test.pl(1) - server stress test program
    mysql-test-run.pl(1) - run MariaDB test suite
    mysql(1) - the MariaDB command-line tool
    mysql.server(1) - MariaDB server startup script
    mysqlaccess(1) - client for checking access privileges
    mysqladmin(1) - client for administering a MariaB server
    mysqlbinlog(1) - utility for processing binary log files
    mysqlbug(1) - generate bug report
    mysqlcheck(1) - a table maintenance program
    mysql_client_test(1) - test client API
    mysql_client_test_embedded(1) - test client API
    mysql_config(1) - get compile options for compiling clients
    mysql_convert_table_format(1) - convert tables to use a given storage engine
    mysqld(8) - the MariaDB server
    mysqld_multi(1) - manage multiple MariaDB servers
    mysqld_safe(1) - MariaDB server startup script
    mysqld_safe_helper(1) - helper script
    mysqldump(1) - a database backup program
    mysqldumpslow(1) - Summarize slow query log files
    mysql_embedded(1) - the MariaDB command-line tool
    mysql_find_rows(1) - extract SQL statements from files
    mysql_fix_extensions(1) - normalize table file name extensions
    mysqlhotcopy(1) - a database backup program
    mysqlimport(1) - a data import program
    mysql_install_db(1) - initialize MariaDB data directory
    mysql_plugin(1) - configure MariaDB server plugins
    mysql_secure_installation(1) - improve MariaDB installation security
    mysql_setpermission(1) - interactively set permissions in grant tables
    mysqlshow(1) - display database, table, and column information
    mysqlslap(1) - load emulation client
    mysqltest(1) - program to run test cases
    mysqltest_embedded(1) - program to run test cases
    mysql_tzinfo_to_sql(1) - load the time zone tables
    mysql_upgrade(1) - check tables for MariaDB upgrade
    mysql_waitpid(1) - kill process and wait for its termination
    mysql_zap(1) - kill processes that match a pattern

top
    namei(1) - follow a pathname until a terminal point is found
    nameif(8) - name network interfaces based on MAC addresses
    namespace.conf(5) - the namespace configuration file
    namespaces(7) - overview of Linux namespaces
    name_to_handle_at(2) - obtain handle for a pathname and open file via a handle
    NAN(3) - floating-point constants
    nan(3) - return 'Not a Number'
    nan(3p) - return quiet NaN
    nanf(3) - return 'Not a Number'
    nanf(3p) - return quiet NaN
    nanl(3) - return 'Not a Number'
    nanl(3p) - return quiet NaN
    nanosleep(2) - high-resolution sleep
    nanosleep(3p) - high resolution sleep
    napms(3x) - low-level curses routines
    nat(8) - stateless native address translation action
    ncat(1) - Concatenate and redirect sockets
    _nc_freeall(3x) - curses memory-leak checking
    _nc_free_and_exit(3x) - curses memory-leak checking
    _nc_free_tinfo(3x) - curses memory-leak checking
    _nc_tracebits(3x) - curses debugging routines
    ncurses(3x) - CRT screen handling and optimization package
    ncurses5-config(1) - helper script for ncurses libraries
    ncurses6-config(1) - helper script for ncurses libraries
    ndbm.h(0p) - definitions for ndbm database operations
    ndiff(1) - Utility to compare the results of Nmap scans
    nearbyint(3) - round to nearest integer
    nearbyint(3p) - point rounding functions
    nearbyintf(3) - round to nearest integer
    nearbyintf(3p) - point rounding functions
    nearbyintl(3) - round to nearest integer
    nearbyintl(3p) - point rounding functions
    needs-restarting(1) - report running processes that have been updated
    neqn(1) - format equations for ascii output
    netcap(8) - a program to see capabilities
    netdb.h(0p) - definitions for network database operations
    netdevice(7) - low-level access to Linux network devices
    NetEm(8) - Network Emulator
    net_if.h(0p) - sockets local interfaces
    netinet_in.h(0p) - Internet address family
    netinet_tcp.h(0p) - definitions for the Internet Transmission Control Protocol (TCP)
    netlink(3) - Netlink macros
    netlink(7) - communication between kernel and user space (AF_NETLINK)
    netsniff-ng(8) - the packet sniffing beast
    netstat(8) - Print network connections, routing tables, interface statistics, masquerade connections, and multicast memberships
    networkctl(1) - Query the status of network links
    networkd.conf(5) - Global Network configuration files
    networkd.conf.d(5) - Global Network configuration files
    network_namespaces(7) - overview of Linux network namespaces
    networks(5) - network name information
    new_field(3x) - create and destroy form fields
    new_form(3x) - create and destroy forms
    newfstatat(2) - get file status
    newgidmap(1) - set the gid mapping of a user namespace
    newgrp(1) - log in to a new group
    newgrp(1p) - change to a new group
    newhelp(1) - generate a performance metrics help database
    new_item(3x) - create and destroy menu items
    newlocale(3) - create, modify, and free a locale object
    newlocale(3p) - create or modify a locale object
    new_menu(3x) - create and destroy menus
    newpad(3x) - create and display curses pads
    new_page(3x) - form pagination functions
    new_pair(3x) - new curses color-pair functions
    newrole(1) - run a shell with a new SELinux role
    newscr(3x) - curses global variables
    _newselect(2) - synchronous I/O multiplexing
    newterm(3x) - curses screen initialization and manipulation routines
    newuidmap(1) - set the uid mapping of a user namespace
    newusers(8) - update and create new users in batch
    newwin(3x) - create curses windows
    nextafter(3) - floating-point number manipulation
    nextafter(3p) - point number
    nextafterf(3) - floating-point number manipulation
    nextafterf(3p) - point number
    nextafterl(3) - floating-point number manipulation
    nextafterl(3p) - point number
    nextdown(3) - return next floating-point number toward positive/negative infinity
    nextdownf(3) - return next floating-point number toward positive/negative infinity
    nextdownl(3) - return next floating-point number toward positive/negative infinity
    nexttoward(3) - floating-point number manipulation
    nexttoward(3p) - point number
    nexttowardf(3) - floating-point number manipulation
    nexttowardf(3p) - point number
    nexttowardl(3) - floating-point number manipulation
    nexttowardl(3p) - point number
    nextup(3) - return next floating-point number toward positive/negative infinity
    nextupf(3) - return next floating-point number toward positive/negative infinity
    nextupl(3) - return next floating-point number toward positive/negative infinity
    nfs(5) - fstab format and options for the nfs file systems
    nfs.conf(5) - general configuration for NFS daemons and tools
    nfs.systemd(7) - managing NFS services through systemd.
    nfs4_acl(5) - NFSv4 Access Control Lists
    nfs4_editfacl(1) - manipulate NFSv4 file/directory access control lists
    nfs4_getfacl(1) - get NFSv4 file/directory access control lists
    nfs4_setfacl(1) - manipulate NFSv4 file/directory access control lists
    nfsconf(8) - Query various NFS configuration settings
    nfsd(7) - special filesystem for controlling Linux NFS server
    nfsd(8) - NFS server process
    nfsdcltrack(8) - NFSv4 Client Tracking Callout Program
    nfsidmap(5) - The NFS idmapper upcall program
    nfsiostat-sysstat(1) - Report input/output statistics for network filesystems (NFS).
    nfsiostat(8) - Emulate iostat for NFS mount points using /proc/self/mountstats
    nfsmount.conf(5) - Configuration file for NFS mounts
    nfsref(8) - manage NFS referrals
    nfsservctl(2) - syscall interface to kernel nfs daemon
    nfsstat(8) - list NFS statistics
    nftw(3) - file tree walk
    nftw(3p) - walk a file tree
    ngettext(1) - translate message and choose plural form
    ngettext(3) - translate message and choose plural form
    nice(1) - run a program with modified scheduling priority
    nice(1p) - invoke a utility with an altered nice value
    nice(2) - change process priority
    nice(3p) - change the nice value of a process
    ninfod(8) - Respond to IPv6 Node Information Queries
    nisdomainname(1) - show or set the system's host name
    nl(1) - number lines of files
    nl(1p) - line numbering filter
    nl(3x) - curses output options
    nl_langinfo(3) - query language and locale information
    nl_langinfo(3p) - language information
    nl_langinfo_l(3) - query language and locale information
    nl_langinfo_l(3p) - language information
    nl_types.h(0p) - data types
    nm(1) - list symbols from object files
    nm(1p) - write the name list of an object file (DEVELOPMENT)
    nmap-update(1) - Updater for Nmap's architecture-independent files
    nmap(1) - Network exploration tool and security / port scanner
    nocbreak(3x) - curses input options
    nodelay(3x) - curses input options
    nodename(1) - show or set the system's host name
    noecho(3x) - curses input options
    nofilter(3x) - miscellaneous curses utility routines
    nohup(1) - run a command immune to hangups, with output to a non-tty
    nohup(1p) - invoke a utility immune to hangups
    nologin(5) - prevent unprivileged users from logging into the system
    nologin(8) - politely refuse a login
    nonl(3x) - curses output options
    noqiflush(3x) - curses input options
    noraw(3x) - curses input options
    notifier(7) - cups notification interface
    notimeout(3x) - curses input options
    nping(1) - Network packet generation tool / ping utility
    nproc(1) - print the number of processing units available
    nptl(7) - Native POSIX Threads Library
    nrand48(3) - generate uniformly distributed pseudo-random numbers
    nrand48(3p) - random non-negative long integers
    nrand48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    nroff(1) - emulate nroff command with groff
    nscd(8) - name service cache daemon
    nscd.conf(5) - name service cache daemon configuration file
    nsenter(1) - run program with namespaces of other processes
    nss-myhostname(8) - Provide hostname resolution for the locally configured system hostname.
    nss-mymachines(8) - Provide hostname resolution for local container instances.
    nss-resolve(8) - Provide hostname resolution via systemd-resolved.service
    nss-systemd(8) - Provide UNIX user and group name resolution for dynamic users and groups.
    nss(5) - Name Service Switch configuration file
    nsswitch.conf(5) - Name Service Switch configuration file
    nstat(8) - network statistics tools.
    ntohl(3) - convert values between host and network byte order
    ntohl(3p) - convert values between host and network byte order
    ntohs(3) - convert values between host and network byte order
    ntohs(3p) - convert values between host and network byte order
    ntp_adjtime(3) - tune kernel clock
    ntp_gettime(3) - get time parameters (NTP daemon interface)
    ntp_gettimex(3) - get time parameters (NTP daemon interface)
    null(4) - data sink
    numa(3) - NUMA policy library
    numa(7) - overview of Non-Uniform Memory Architecture
    numactl(8) - Control NUMA policy for processes or shared memory
    numa_maps(5) - overview of Non-Uniform Memory Architecture
    numastat(8) - Show per-NUMA-node memory statistics for processes and the operating system
    numcodes(3x) - curses terminfo global variables
    numfmt(1) - Convert numbers from/to human-readable strings
    numfnames(3x) - curses terminfo global variables
    numnames(3x) - curses terminfo global variables

top
    objcopy(1) - copy and translate object files
    objdump(1) - display information from object files.
    ocount(1) - Event counting tool for Linux
    ocsptool(1) - GnuTLS OCSP tool
    od(1) - dump files in octal and other formats
    od(1p) - dump files in various formats
    offsetof(3) - offset of a structure member
    oldfstat(2) - get file status
    oldlstat(2) - get file status
    oldolduname(2) - get name and information about current kernel
    oldstat(2) - get file status
    olduname(2) - get name and information about current kernel
    on_exit(3) - register a function to be called at normal process termination
    op-check-perfevents(1) - checks for kernel perf pmu support
    opannotate(1) - produce source or assembly annotated with profile data
    oparchive(1) - produce archive of oprofile data for offline analysis
    opcontrol(1) - control OProfile profiling
    open(2) - open and possibly create a file
    open(3p) - open file relative to directory file descriptor
    openat(2) - open and possibly create a file
    openat(3p) - open file relative to directory file descriptor
    open_by_handle(3) - file handle operations
    open_by_handle_at(2) - obtain handle for a pathname and open file via a handle
    opendir(3) - open a directory
    opendir(3p) - open directory associated with file descriptor
    open_init_pty(8) - run an program under a pseudo terminal
    openlog(3) - send messages to the system logger
    openlog(3p) - open a connection to the logging facility
    open_memstream(3) - open a dynamic memory buffer stream
    open_memstream(3p) - open a dynamic memory buffer stream
    openpty(3) - terminal utility functions
    openvt(1) - start a program on a new virtual terminal (VT).
    open_wmemstream(3) - open a dynamic memory buffer stream
    open_wmemstream(3p) - open a dynamic memory buffer stream
    operator(7) - C operator precedence and order of evaluation
    operf(1) - Performance profiler tool for Linux
    opgprof(1) - produce gprof-format profile data
    ophelp(1) - list OProfile events
    opimport(1) - converts sample database files
    opjitconv(1) - convert jit dump file to an ELF
    opreport(1) - produce symbol or binary image summaries
    oprofile(1) - a statistical profiler for Linux systems, capable of profiling all running code at low overhead; also included is a set of post-profiling analysis tools, as well as a simple event counting tool
    oprof_start(1) - A GUI interface for OProfile
    optarg(3) - Parse command-line options
    optarg(3p) - options parsing variables
    opterr(3) - Parse command-line options
    opterr(3p) - command option parsing
    optind(3) - Parse command-line options
    optind(3p) - command option parsing
    optopt(3) - Parse command-line options
    optopt(3p) - command option parsing
    os-release(5) - Operating system identification
    ospeed(3x) - direct curses interface to the terminfo capability database
    outb(2) - port I/O
    outb_p(2) - port I/O
    outl(2) - port I/O
    outl_p(2) - port I/O
    outsb(2) - port I/O
    outsl(2) - port I/O
    outsw(2) - port I/O
    outw(2) - port I/O
    outw_p(2) - port I/O
    overlay(3x) - overlay and manipulate overlapped curses windows
    overwrite(3x) - overlay and manipulate overlapped curses windows
    ovn-architecture(7) - Open Virtual Network architecture
    ovn-controller-vtep(8) - Open Virtual Network local controller for vtep enabled physical switches.
    ovn-controller(8) - Open Virtual Network local controller
    ovn-ctl(8) - Open Virtual Network northbound daemon lifecycle utility
    ovn-detrace(1) - convert ``ovs-appctl ofproto/trace'' output to combine OVN logical flow information.
    ovn-nb(5) - OVN_Northbound database schema
    ovn-nbctl(8) - Open Virtual Network northbound db management utility
    ovn-northd(8) - Open Virtual Network central control daemon
    ovn-sb(5) - OVN_Southbound database schema
    ovn-sbctl(8) - utility for querying and configuring OVN_Southbound database
    ovn-trace(8) - Open Virtual Network logical network tracing utility
    ovs-appctl(8) - utility for configuring running Open vSwitch daemons
    ovs-bugtool(8) - Open vSwitch bug reporting utility
    ovs-ctl(8) - OVS startup helper script
    ovs-dpctl-top(8) - Top like behavior for ovs-dpctl dump-flows
    ovs-dpctl(8) - administer Open vSwitch datapaths
    ovs-fields(7) - protocol header fields in OpenFlow and Open vSwitch
    ovs-kmod-ctl(8) - OVS startup helper script for loading kernel modules
    ovs-l3ping(8) - check network deployment for L3 tunneling problems
    ovs-ofctl(8) - administer OpenFlow switches
    ovs-parse-backtrace(8) - parses ovs-appctl backtrace output
    ovs-pcap(1) - print packets from a pcap file as hex
    ovs-pki(8) - OpenFlow public key infrastructure management utility
    ovs-sim(1) - Open vSwitch simulator environment
    ovs-tcpdump(8) - Dump traffic from an Open vSwitch port using tcpdump.
    ovs-tcpundump(1) - convert ``tcpdump -xx'' output to hex strings
    ovs-testcontroller(8) - simple OpenFlow controller for testing
    ovs-vlan-bug-workaround(8) - utility for configuring Linux VLAN driver bug workaround
    ovs-vsctl(8) - utility for querying and configuring ovs-vswitchd
    ovs-vswitchd(8) - Open vSwitch daemon
    ovs-vswitchd.conf.db(5) - Open_vSwitch database schema
    ovsdb-client(1) - command-line interface to ovsdb-server(1)
    ovsdb-idlc(1) - Open vSwitch IDL (Interface Definition Language) compiler
    ovsdb-server(1) - Open vSwitch database server
    ovsdb-server(5) - _Server database schema
    ovsdb-tool(1) - Open vSwitch database management utility

top
    p11tool(1) - GnuTLS PKCS #11 tool
    package-cleanup(1) - clean up locally installed, duplicate, or orphaned packages
    packet(7) - packet interface on device level
    pair_content(3x) - curses color manipulation routines
    PAIR_NUMBER(3x) - curses color manipulation routines
    pam(3) - Pluggable Authentication Modules Library
    PAM(8) - Pluggable Authentication Modules for Linux
    pam(8) - Pluggable Authentication Modules for Linux
    pam.conf(5) - PAM configuration files
    pam.d(5) - PAM configuration files
    pam_access(8) - PAM module for logdaemon style login access control
    pam_acct_mgmt(3) - PAM account validation management
    pam_authenticate(3) - account authentication
    pam_chauthtok(3) - updating authentication tokens
    pam_close_session(3) - terminate PAM session management
    pam_conv(3) - PAM conversation function
    pam_cracklib(8) - PAM module to check the password against dictionary words
    pam_debug(8) - PAM module to debug the PAM stack
    pam_deny(8) - The locking-out PAM module
    pam_echo(8) - PAM module for printing text messages
    pam_end(3) - termination of PAM transaction
    pam_env(8) - PAM module to set/unset environment variables
    pam_env.conf(5) - the environment variables config files
    pam_error(3) - display error messages to the user
    pam_exec(8) - PAM module which calls an external command
    pam_fail_delay(3) - request a delay on failure
    pam_faildelay(8) - Change the delay on failure per-application
    pam_filter(8) - PAM filter module
    pam_ftp(8) - PAM module for anonymous access module
    pam_get_authtok(3) - get authentication token
    pam_get_authtok_noverify(3) - get authentication token
    pam_get_authtok_verify(3) - get authentication token
    pam_get_data(3) - get module internal data
    pam_getenv(3) - get a PAM environment variable
    pam_getenvlist(3) - getting the PAM environment
    pam_get_item(3) - getting PAM informations
    pam_get_user(3) - get user name
    pam_group(8) - PAM module for group access
    pam_info(3) - display messages to the user
    pam_issue(8) - PAM module to add issue file to user prompt
    pam_keyinit(8) - Kernel session keyring initialiser module
    pam_lastlog(8) - PAM module to display date of last login and perform inactive account lock out
    pam_limits(8) - PAM module to limit resources
    pam_listfile(8) - deny or allow services based on an arbitrary file
    pam_localuser(8) - require users to be listed in /etc/passwd
    pam_loginuid(8) - Record user's login uid to the process attribute
    pam_mail(8) - Inform about available mail
    pam_misc_drop_env(3) - liberating a locally saved environment
    pam_misc_paste_env(3) - transcribing an environment to that of PAM
    pam_misc_setenv(3) - BSD like PAM environment variable setting
    pam_mkhomedir(8) - PAM module to create users home directory
    pam_motd(8) - Display the motd file
    pam_namespace(8) - PAM module for configuring namespace for a session
    pam_nologin(8) - Prevent non-root users from login
    pam_open_session(3) - start PAM session management
    pam_permit(8) - The promiscuous module
    pam_prompt(3) - interface to conversation function
    pam_putenv(3) - set or change PAM environment variable
    pam_pwhistory(8) - PAM module to remember last passwords
    pam_rhosts(8) - The rhosts PAM module
    pam_rootok(8) - Gain only root access
    pam_securetty(8) - Limit root login to special devices
    pam_selinux(8) - PAM module to set the default security context
    pam_selinux_check(8) - login program to test pam_selinux.so
    pam_sepermit(8) - PAM module to allow/deny login depending on SELinux enforcement state
    pam_setcred(3) - establish / delete user credentials
    pam_set_data(3) - set module internal data
    pam_set_item(3) - set and update PAM informations
    pam_shells(8) - PAM module to check for valid login shell
    pam_sm_acct_mgmt(3) - PAM service function for account management
    pam_sm_authenticate(3) - PAM service function for user authentication
    pam_sm_chauthtok(3) - PAM service function for authentication token management
    pam_sm_close_session(3) - PAM service function to terminate session management
    pam_sm_open_session(3) - PAM service function to start session management
    pam_sm_setcred(3) - PAM service function to alter credentials
    pam_start(3) - initialization of PAM transaction
    pam_strerror(3) - return string describing PAM error code
    pam_succeed_if(8) - test account characteristics
    pam_syslog(3) - send messages to the system logger
    pam_systemd(8) - Register user sessions in the systemd login manager
    pam_tally(8) - The login counter (tallying) module
    pam_tally2(8) - The login counter (tallying) module
    pam_time(8) - PAM module for time control access
    pam_timestamp(8) - Authenticate using cached successful authentication attempts
    pam_timestamp_check(8) - Check to see if the default timestamp is valid
    pam_tty_audit(8) - Enable or disable TTY auditing for specified users
    pam_umask(8) - PAM module to set the file mode creation mask
    pam_unix(8) - Module for traditional password authentication
    pam_userdb(8) - PAM module to authenticate against a db database
    pam_verror(3) - display error messages to the user
    pam_vinfo(3) - display messages to the user
    pam_vprompt(3) - interface to conversation function
    pam_vsyslog(3) - send messages to the system logger
    pam_warn(8) - PAM module which logs all PAM items if called
    pam_wheel(8) - Only permit root access to members of group wheel
    pam_xauth(8) - PAM module to forward xauth keys between users
    pam_xauth_data(3) - structure containing X authentication data
    panel(3x) - panel stack extension for curses
    parted(8) - a partition manipulation program
    partprobe(8) - inform the OS of partition table changes
    partx(8) - tell the kernel about the presence and numbering of on-disk partitions
    passwd(1) - change user password
    passwd(5) - password file
    passwd2des(3) - RFS password encryption
    paste(1) - merge lines of files
    paste(1p) - merge corresponding or subsequent lines of files
    patch(1) - apply a diff file to an original
    patch(1p) - apply changes to files
    pathchk(1) - check whether file names are valid or portable
    pathchk(1p) - check pathnames
    pathconf(3) - get configuration values for files
    pathconf(3p) - get configurable pathname variables
    path_resolution(7) - how a pathname is resolved to a file
    path_to_fshandle(3) - file handle operations
    path_to_handle(3) - file handle operations
    pause(2) - wait for signal
    pause(3p) - suspend the thread until a signal is received
    pax(1p) - portable archive interchange
    PC(3x) - direct curses interface to the terminfo capability database
    pcap-config(1) - write libpcap compiler and linker flags to standard output
    pcap(3pcap) - Packet Capture library
    pcap_activate(3pcap) - activate a capture handle
    pcap_breakloop(3pcap) - force a pcap_dispatch() or pcap_loop() call to return
    pcap_can_set_rfmon(3pcap) - check whether monitor mode can be set for a not-yet-activated capture handle
    pcap_close(3pcap) - close a capture device or savefile
    pcap_compile(3pcap) - compile a filter expression
    pcap_create(3pcap) - create a live capture handle
    pcap_datalink(3pcap) - get the link-layer header type
    pcap_datalink_name_to_val(3pcap) - get the link-layer header type value corresponding to a header type name
    pcap_datalink_val_to_description(3pcap) - get a name or description for a link-layer header type value
    pcap_datalink_val_to_name(3pcap) - get a name or description for a link-layer header type value
    pcap_dispatch(3pcap) - process packets from a live capture or savefile
    pcap_dump(3pcap) - write a packet to a capture file
    pcap_dump_close(3pcap) - close a savefile being written to
    pcap_dump_file(3pcap) - get the standard I/O stream for a savefile being written
    pcap_dump_flush(3pcap) - flush to a savefile packets dumped
    pcap_dump_fopen(3pcap) - open a file to which to write packets
    pcap_dump_ftell(3pcap) - get the current file offset for a savefile being written
    pcap_dump_ftell64(3pcap) - get the current file offset for a savefile being written
    pcap_dump_open(3pcap) - open a file to which to write packets
    pcap_file(3pcap) - get the standard I/O stream for a savefile being read
    pcap_fileno(3pcap) - get the file descriptor for a live capture
    pcap_findalldevs(3pcap) - get a list of capture devices, and free that list
    pcap_fopen_offline(3pcap) - open a saved capture file for reading
    pcap_fopen_offline_with_tstamp_precision(3pcap) - open a saved capture file for reading
    pcap_freealldevs(3pcap) - get a list of capture devices, and free that list
    pcap_freecode(3pcap) - free a BPF program
    pcap_free_datalinks(3pcap) - get a list of link-layer header types supported by a capture device, and free that list
    pcap_free_tstamp_types(3pcap) - get a list of time stamp types supported by a capture device, and free that list
    pcap_geterr(3pcap) - get or print libpcap error message text
    pcap_getnonblock(3pcap) - set or get the state of non-blocking mode on a capture device
    pcap_get_required_select_timeout(3pcap) - get a file descriptor on which a select() can be done for a live capture
    pcap_get_selectable_fd(3pcap) - get a file descriptor on which a select() can be done for a live capture
    pcap_get_tstamp_precision(3pcap) - get the time stamp precision returned in captures
    pcap_inject(3pcap) - transmit a packet
    pcap_is_swapped(3pcap) - find out whether a savefile has the native byte order
    pcap_lib_version(3pcap) - get the version information for libpcap
    pcap_list_datalinks(3pcap) - get a list of link-layer header types supported by a capture device, and free that list
    pcap_list_tstamp_types(3pcap) - get a list of time stamp types supported by a capture device, and free that list
    pcap_lookupdev(3pcap) - find the default device on which to capture
    pcap_lookupnet(3pcap) - find the IPv4 network number and netmask for a device
    pcap_loop(3pcap) - process packets from a live capture or savefile
    pcap_major_version(3pcap) - get the version number of a savefile
    pcap_minor_version(3pcap) - get the version number of a savefile
    pcap_next(3pcap) - read the next packet from a pcap_t
    pcap_next_ex(3pcap) - read the next packet from a pcap_t
    pcap_offline_filter(3pcap) - check whether a filter matches a packet
    pcap_open_dead(3pcap) - open a fake pcap_t for compiling filters or opening a capture for output
    pcap_open_dead_with_tstamp_precision(3pcap) - open a fake pcap_t for compiling filters or opening a capture for output
    pcap_open_live(3pcap) - open a device for capturing
    pcap_open_offline(3pcap) - open a saved capture file for reading
    pcap_open_offline_with_tstamp_precision(3pcap) - open a saved capture file for reading
    pcap_perror(3pcap) - get or print libpcap error message text
    pcap_sendpacket(3pcap) - transmit a packet
    pcap_set_buffer_size(3pcap) - set the buffer size for a not-yet-activated capture handle
    pcap_set_datalink(3pcap) - set the link-layer header type to be used by a capture device
    pcap_setdirection(3pcap) - set the direction for which packets will be captured
    pcap_setfilter(3pcap) - set the filter
    pcap_set_immediate_mode(3pcap) - set immediate mode for a not-yet-activated capture handle
    pcap_setnonblock(3pcap) - set or get the state of non-blocking mode on a capture device
    pcap_set_promisc(3pcap) - set promiscuous mode for a not-yet-activated capture handle
    pcap_set_protocol_linux(3pcap) - set capture protocol for a not-yet-activated capture handle
    pcap_set_rfmon(3pcap) - set monitor mode for a not-yet-activated capture handle
    pcap_set_snaplen(3pcap) - set the snapshot length for a not-yet-activated capture handle
    pcap_set_timeout(3pcap) - set the packet buffer timeout for a not-yet-activated capture handle
    pcap_set_tstamp_precision(3pcap) - set the time stamp precision returned in captures
    pcap_set_tstamp_type(3pcap) - set the time stamp type to be used by a capture device
    pcap_snapshot(3pcap) - get the snapshot length
    pcap_stats(3pcap) - get capture statistics
    pcap_statustostr(3pcap) - convert a PCAP_ERROR_ or PCAP_WARNING_ value to a string
    pcap_strerror(3pcap) - convert an errno value to a string
    pcap_tstamp_type_name_to_val(3pcap) - get the time stamp type value corresponding to a time stamp type name
    pcap_tstamp_type_val_to_description(3pcap) - get a name or description for a time stamp type value
    pcap_tstamp_type_val_to_name(3pcap) - get a name or description for a time stamp type value
    pciconfig_iobase(2) - pci device information handling
    pciconfig_read(2) - pci device information handling
    pciconfig_write(2) - pci device information handling
    pcilib(7) - a library for accessing PCI devices
    pclose(3) - pipe stream to or from a process
    pclose(3p) - close a pipe stream to or from a process
    pcp-atop(1) - Advanced System and Process Monitor
    pcp-atoprc(5) - pcp-atop/pcp-atopsar related resource file
    pcp-atopsar(1) - Advanced System Activity Report (pcp-atop related)
    pcp-collectl(1) - collect data that describes the current system status
    pcp-dmcache(1) - report on logical storage device caches
    pcp-dstat(1) - versatile tool for generating system resource statistics
    pcp-dstat(5) - pcp-dstat configuration file
    pcp-free(1) - report on free and used memory in the system
    pcp-iostat(1) - performance metrics i/o statistics tool
    pcp-ipcs(1) - provide information on IPC facilities
    pcp-kube-pods(1) - list Kubernetes pods to scan for running PCP services
    pcp-lvmcache(1) - report on logical storage device caches
    pcp-mpstat(1) - Report CPU and Interrupt related statistics.
    pcp-numastat(1) - report on NUMA memory allocation
    pcp-pidstat(1) - Report statistics for Linux tasks.
    pcp-python(1) - run a python script using a preferred python variant
    pcp-shping(1) - report on shell service availability and response
    pcp-summary(1) - run a command or summarize an installation
    pcp-tapestat(1) - performance metrics i/o tape statistics tool
    pcp-uptime(1) - tell how long the system has been running
    pcp-verify(1) - verify aspects of a PCP installation
    pcp-vmstat(1) - high-level system performance overview
    pcp(1) - run a command or summarize an installation
    pcp.conf(5) - the Performance Co-Pilot configuration and environment file
    pcp.env(5) - script to set Performance Co-Pilot run-time environment variables
    pcp2csv(1) - performance metrics reporter
    pcp2elasticsearch(1) - pcp-to-elasticsearch metrics exporter
    pcp2graphite(1) - pcp-to-graphite metrics exporter
    pcp2influxdb(1) - pcp-to-influxdb metrics exporter
    pcp2json(1) - pcp-to-json metrics exporter
    pcp2spark(1) - pcp-to-spark metrics exporter
    pcp2xlsx(1) - pcp-to-xlsx metrics exporter
    pcp2xml(1) - pcp-to-xml metrics exporter
    pcp2zabbix(1) - pcp-to-zabbix metrics exporter
    PCPIntro(1) - introduction to the Performance Co-Pilot (PCP)
    pcpintro(1) - introduction to the Performance Co-Pilot (PCP)
    PCPIntro(3) - introduction to the Performance Co-Pilot (PCP) libraries
    pcpintro(3) - introduction to the Performance Co-Pilot (PCP) libraries
    pcre-config(1) - program to return PCRE configuration
    PCRE(3) - Perl-compatible regular expressions
    pcre(3) - Perl-compatible regular expressions (original API)
    pcre16(3) - Perl-compatible regular expressions
    pcre32(3) - Perl-compatible regular expressions
    pcreapi(3) - Perl-compatible regular expressions
    pcre_assign_jit_stack(3) - Perl-compatible regular expressions
    pcrebuild(3) - Perl-compatible regular expressions
    pcrecallout(3) - Perl-compatible regular expressions
    pcrecompat(3) - Perl-compatible regular expressions
    pcre_compile(3) - Perl-compatible regular expressions
    pcre_compile2(3) - Perl-compatible regular expressions
    pcre_config(3) - Perl-compatible regular expressions
    pcre_copy_named_substring(3) - Perl-compatible regular expressions
    pcre_copy_substring(3) - Perl-compatible regular expressions
    pcrecpp(3) - Perl-compatible regular expressions.
    pcredemo(3) -
    pcre_dfa_exec(3) - Perl-compatible regular expressions
    pcre_exec(3) - Perl-compatible regular expressions
    pcre_free_study(3) - Perl-compatible regular expressions
    pcre_free_substring(3) - Perl-compatible regular expressions
    pcre_free_substring_list(3) - Perl-compatible regular expressions
    pcre_fullinfo(3) - Perl-compatible regular expressions
    pcre_get_named_substring(3) - Perl-compatible regular expressions
    pcre_get_stringnumber(3) - Perl-compatible regular expressions
    pcre_get_stringtable_entries(3) - Perl-compatible regular expressions
    pcre_get_substring(3) - Perl-compatible regular expressions
    pcre_get_substring_list(3) - Perl-compatible regular expressions
    pcregrep(1) - a grep with Perl-compatible regular expressions.
    pcrejit(3) - Perl-compatible regular expressions
    pcre_jit_exec(3) - Perl-compatible regular expressions
    pcre_jit_stack_alloc(3) - Perl-compatible regular expressions
    pcre_jit_stack_free(3) - Perl-compatible regular expressions
    pcrelimits(3) - Perl-compatible regular expressions
    pcre_maketables(3) - Perl-compatible regular expressions
    pcrematching(3) - Perl-compatible regular expressions
    pcrepartial(3) - Perl-compatible regular expressions
    pcrepattern(3) - Perl-compatible regular expressions
    pcre_pattern_to_host_byte_order(3) - Perl-compatible regular expressions
    pcreperform(3) - Perl-compatible regular expressions
    pcreposix(3) - Perl-compatible regular expressions.
    pcreprecompile(3) - Perl-compatible regular expressions
    pcre_refcount(3) - Perl-compatible regular expressions
    pcresample(3) - Perl-compatible regular expressions
    pcrestack(3) - Perl-compatible regular expressions
    pcre_study(3) - Perl-compatible regular expressions
    pcresyntax(3) - Perl-compatible regular expressions
    pcretest(1) - a program for testing Perl-compatible regular expressions.
    pcreunicode(3) - Perl-compatible regular expressions
    pcre_utf16_to_host_byte_order(3) - Perl-compatible regular expressions
    pcre_utf32_to_host_byte_order(3) - Perl-compatible regular expressions
    pcre_version(3) - Perl-compatible regular expressions
    pdfmom(1) - Produce PDF documents using the mom macro set
    pdfroff(1) - create PDF documents using groff
    pechochar(3x) - create and display curses pads
    pecho_wchar(3x) - create and display curses pads
    pedit(8) - generic packet editor action
    peekfd(1) - peek at file descriptors of running processes
    perf-annotate(1) - Read perf.data (created by perf record) and display annotated code
    perf-archive(1) - Create archive with object files with build-ids found in perf.data file
    perf-bench(1) - General framework for benchmark suites
    perf-buildid-cache(1) - Manage build-id cache.
    perf-buildid-list(1) - List the buildids in a perf.data file
    perf-c2c(1) - Shared Data C2C/HITM Analyzer.
    perf-config(1) - Get and set variables in a configuration file.
    perf-data(1) - Data file related processing
    perf-diff(1) - Read perf.data files and display the differential profile
    perf-evlist(1) - List the event names in a perf.data file
    perf-ftrace(1) - simple wrapper for kernel's ftrace functionality
    perf-help(1) - display help information about perf
    perf-inject(1) - Filter to augment the events stream with additional information
    perf-kallsyms(1) - Searches running kernel for symbols
    perf-kmem(1) - Tool to trace/measure kernel memory properties
    perf-kvm(1) - Tool to trace/measure kvm guest os
    perf-list(1) - List all symbolic event types
    perf-lock(1) - Analyze lock events
    perf-mem(1) - Profile memory accesses
    perf-probe(1) - Define new dynamic tracepoints
    perf-record(1) - Run a command and record its profile into perf.data
    perf-report(1) - Read perf.data (created by perf record) and display the profile
    perf-sched(1) - Tool to trace/measure scheduler properties (latencies)
    perf-script-perl(1) - Process trace data with a Perl script
    perf-script-python(1) - Process trace data with a Python script
    perf-script(1) - Read perf.data (created by perf record) and display trace output
    perf-stat(1) - Run a command and gather performance counter statistics
    perf-test(1) - Runs sanity tests.
    perf-timechart(1) - Tool to visualize total system behavior during a workload
    perf-top(1) - System profiling tool.
    perf-trace(1) - strace inspired tool
    perf-version(1) - display the version of perf binary
    perf(1) - Performance analysis tools for Linux
    perfalloc(1) - notify pmdaperfevent(1) to disable hardware counter allocation.
    perfevent.conf(5) - the Performance Co-Pilot perfevent PMDA configuration file
    perf_event_open(2) - set up performance monitoring
    perfmonctl(2) - interface to IA-64 performance monitoring unit
    perror(1) - explain error codes
    perror(3) - print a system error message
    perror(3p) - write error messages to standard error
    persistent-keyring(7) - per-user persistent keyring
    personality(2) - set the process execution domain
    pfbtops(1) - translate a PostScript font in .pfb format to ASCII
    pfifo(8) - Packet limited First In, First Out queue
    pfifo_fast(8) - three-band first in, first out queue
    pfm_find_event(3) -
    pfm_get_event_attr_info(3) - get event attribute information
    pfm_get_event_encoding(3) - get raw event encoding
    pfm_get_event_info(3) - get event information
    pfm_get_event_next(3) - iterate over events
    pfm_get_os_event_encoding(3) - get event encoding for a specific operating system
    pfm_get_perf_event_encoding(3) - encode event for perf_event API
    pfm_get_pmu_info(3) - get PMU information
    pfm_get_version(3) - get library version
    pfm_initialize(3) - initialize library
    pfm_strerror(3) - return constant string describing error code
    pfm_terminate(3) - free resources used by library
    pg(1) - browse pagewise through text files
    pg3(8) - send stream of UDP packets
    pgrep(1) - look up or signal processes based on name and other attributes
    pgset(8) - send stream of UDP packets
    phys(2) - unimplemented system calls
    pic(1) - compile pictures for troff or TeX
    pic2graph(1) - convert a PIC diagram into a cropped image
    pid_namespaces(7) - overview of Linux PID namespaces
    pidof(1) - find the process ID of a running program.
    pidstat(1) - Report statistics for Linux tasks.
    PIE(8) - Proportional Integral controller-Enhanced AQM algorithm
    ping(8) - send ICMP ECHO_REQUEST to network hosts
    pinky(1) - lightweight finger
    pipe(2) - create pipe
    pipe(3p) - create an interprocess channel
    pipe(7) - overview of pipes and FIFOs
    pipe2(2) - create pipe
    pivot_root(2) - change the root filesystem
    pivot_root(8) - change the root filesystem
    pkey_alloc(2) - allocate or free a protection key
    pkey_free(2) - allocate or free a protection key
    pkey_mprotect(2) - set protection on a region of memory
    pkeys(7) - overview of Memory Protection Keys
    pkill(1) - look up or signal processes based on name and other attributes
    pldd(1) - display dynamic shared objects linked into a process
    plipconfig(8) - fine tune PLIP device parameters
    __pmAddIPC(3) - IPC version infrastructure support
    pmAddProfile(3) - add instance(s) to the current PMAPI instance profile
    pmaddprofile(3) - add instance(s) to the current PMAPI instance profile
    __pmaf(3) - event queue services for periodic asynchronous callbacks
    __pmAFblock(3) - event queue services for periodic asynchronous callbacks
    __pmAFisempty(3) - event queue services for periodic asynchronous callbacks
    pmafm(1) - Performance Co-Pilot archive folio manager
    pmafm(3) - record mode support for PMAPI clients
    __pmAFregister(3) - event queue services for periodic asynchronous callbacks
    __pmAFsetup(3) - event queue services for periodic asynchronous callbacks
    __pmAFunblock(3) - event queue services for periodic asynchronous callbacks
    __pmAFunregister(3) - event queue services for periodic asynchronous callbacks
    pmap(1) - report memory map of a process
    pmap_getmaps(3) - library routines for remote procedure calls
    pmap_getport(3) - library routines for remote procedure calls
    PMAPI(3) - introduction to the Performance Metrics Application Programming Interface
    pmapi(3) - introduction to the Performance Metrics Application Programming Interface
    PMAPI_INTERNAL(3) - internal details for the Performance Metrics Application Programming Interface
    pmapi_internal(3) - internal details for the Performance Metrics Application Programming Interface
    pmap_rmtcall(3) - library routines for remote procedure calls
    pmap_set(3) - library routines for remote procedure calls
    pmap_unset(3) - library routines for remote procedure calls
    pmAtomStr(3) - convert a performance metric value into a string
    pmatomstr(3) - convert a performance metric value into a string
    pmAtomStr_r(3) - convert a performance metric value into a string
    pmcd(1) - performance metrics collector daemon
    pmcd_wait(1) - wait for PMCD to accept client connections
    pmchart(1) - strip chart tool for Performance Co-Pilot
    pmClearDebug(3) - manipulate PCP debugging control options
    pmClearFetchGroup(3) - simplified performance metrics value fetch and conversion
    pmclient(1) - a simple performance metrics client
    pmclient_fg(1) - a simple performance metrics client
    pmcollectl(1) - collect data that describes the current system status
    pmconfig(1) - Performance Co-Pilot configuration parameters
    pmconfirm(1) - general purpose dialog box
    __pmConnectLogger(3) - connect to a performance metrics logger control port
    __pmconnectlogger(3) - connect to a performance metrics logger control port
    __pmControlLog(3) - enable, disable or enquire about logging of performance metrics
    __pmcontrollog(3) - enable, disable or enquire about logging of performance metrics
    __pmConvertTime(3) - convert tm structure to timeval structure
    __pmconverttime(3) - convert tm structure to timeval structure
    pmConvScale(3) - rescale a performance metric value
    pmconvscale(3) - rescale a performance metric value
    pmcpp(1) - simple preprocessor for the Performance Co-Pilot
    pmCreateFetchGroup(3) - simplified performance metrics value fetch and conversion
    pmCtime(3) - format the date and time for a reporting timezone
    pmctime(3) - format the date and time for a reporting timezone
    PMDA(3) - introduction to the Performance Metrics Domain Agent support library
    pmda(3) - introduction to the Performance Metrics Domain Agent support library
    pmdaactivemq(1) - ActiveMQ performance metrics domain agent (PMDA)
    pmdaaix(1) - operating system kernel performance metrics domain agents
    pmdaapache(1) - Apache2 web server performance metrics domain agent (PMDA)
    pmdaAttribute(3) - informs a PMDA about client connection attributes
    pmdaattribute(3) - informs a PMDA about client connection attributes
    pmdabash(1) - Bourne-Again SHell trace performance metrics domain agent
    pmdabcc(1) - BCC PMDA
    pmdabind2(1) - BIND performance metrics domain agent (PMDA)
    pmdabonding(1) - Linux bonded interface performance metrics domain agent (PMDA)
    pmdacache(3) - manage a cache of instance domain information for a PMDA
    pmdaCacheLookup(3) - manage a cache of instance domain information for a PMDA
    pmdaCacheLookupKey(3) - manage a cache of instance domain information for a PMDA
    pmdaCacheLookupName(3) - manage a cache of instance domain information for a PMDA
    pmdaCacheOp(3) - manage a cache of instance domain information for a PMDA
    pmdaCachePurge(3) - manage a cache of instance domain information for a PMDA
    pmdaCacheResize(3) - manage a cache of instance domain information for a PMDA
    pmdaCacheStore(3) - manage a cache of instance domain information for a PMDA
    pmdaCacheStoreKey(3) - manage a cache of instance domain information for a PMDA
    pmdaChildren(3) - translate a PMID to a set of dynamic performance metric names
    pmdachildren(3) - translate a PMID to a set of dynamic performance metric names
    pmdacifs(1) - Common Internet Filesystem (CIFS) PMDA
    pmdacisco(1) - Cisco router performance metrics domain agent (PMDA)
    pmdaCloseHelp(3) - help text support for a PMDA
    pmdaConnect(3) - establish a connection between a daemon PMDA and PMCD
    pmdaconnect(3) - establish a connection between a daemon PMDA and PMCD
    pmdaDaemon(3) - initialize the PMDA to run as a daemon
    pmdadaemon(3) - initialize the PMDA to run as a daemon
    pmdadarwin(1) - operating system kernel performance metrics domain agents
    pmdadbping(1) - database response time and availability PMDA
    pmdaDesc(3) - get the description of a metric from a PMDA
    pmdadesc(3) - get the description of a metric from a PMDA
    pmdadm(1) - Device Mapper PMDA
    pmdadocker(1) - docker performance metrics domain agent (PMDA)
    pmdads389(1) - 389 Directory Server PMDA
    pmdads389log(1) - 389 Directory Server Log PMDA
    pmdaDSO(3) - initialize the PMDA to run as a DSO
    pmdadso(3) - initialize the PMDA to run as a DSO
    pmdaelasticsearch(1) - elasticsearch performance metrics domain agent (PMDA)
    pmdaEventAddHighResMissedRecord(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventAddHighResRecord(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventAddMissedRecord(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventAddParam(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventAddRecord(3) - utilities for PMDAs to build packed arrays of event records
    pmdaeventarray(3) - utilities for PMDAs to build packed arrays of event records
    pmdaeventclient(3) - client context tracking interfaces for event queues
    pmdaEventClients(3) - client context tracking interfaces for event queues
    pmdaEventEndClient(3) - client context tracking interfaces for event queues
    pmdaEventGetAddr(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventHighResAddParam(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventHighResGetAddr(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventNewActiveQueue(3) - utilities for PMDAs managing event queues
    pmdaEventNewArray(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventNewClient(3) - client context tracking interfaces for event queues
    pmdaEventNewHighResArray(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventNewQueue(3) - utilities for PMDAs managing event queues
    pmdaeventqueue(3) - utilities for PMDAs managing event queues
    pmdaEventQueueAppend(3) - utilities for PMDAs managing event queues
    pmdaEventQueueBytes(3) - utilities for PMDAs managing event queues
    pmdaEventQueueClients(3) - utilities for PMDAs managing event queues
    pmdaEventQueueCounter(3) - utilities for PMDAs managing event queues
    pmdaEventQueueHandle(3) - utilities for PMDAs managing event queues
    pmdaEventQueueMemory(3) - utilities for PMDAs managing event queues
    pmdaEventQueueRecords(3) - utilities for PMDAs managing event queues
    pmdaEventQueueShutdown(3) - utilities for PMDAs managing event queues
    pmdaEventReleaseArray(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventReleaseHighResArray(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventResetArray(3) - utilities for PMDAs to build packed arrays of event records
    pmdaEventResetHighResArray(3) - utilities for PMDAs to build packed arrays of event records
    pmdaExtSetFlags(3) - initialize a PMDA
    pmdaFetch(3) - fill a pmResult structure with the requested metric values
    pmdafetch(3) - fill a pmResult structure with the requested metric values
    pmdafreebsd(1) - operating system kernel performance metrics domain agents
    pmdaGetContext(3) - generic PDU processing for a PMDA
    pmdaGetHelp(3) - help text support for a PMDA
    pmdaGetInDomHelp(3) - help text support for a PMDA
    pmdaGetOpt(3) - get options from arguments, parsing generic PMDA options
    pmdaGetOptions(3) - get options from arguments, parsing generic PMDA options
    pmdagetoptions(3) - get options from arguments, parsing generic PMDA options
    pmdagfs2(1) - Global Filesystem v2 (GFS2) PMDA
    pmdagluster(1) - Gluster Filesystem PMDA
    pmdagpfs(1) - gpfs filesystem statistics performance metrics domain agent (PMDA)
    pmdahaproxy(1) - HAProxy PMDA
    pmdahelp(3) - help text support for a PMDA
    pmdaib(1) - Infiniband performance metrics domain agent (PMDA)
    pmdaInit(3) - initialize a PMDA
    pmdainit(3) - initialize a PMDA
    pmdaInstance(3) - return instance descriptions for a PMDA
    pmdainstance(3) - return instance descriptions for a PMDA
    pmdaInterfaceMoved(3) - reset internal state of a pmdaInterface structure
    pmdainterfacemoved(3) - reset internal state of a pmdaInterface structure
    pmdajbd2(1) - journal block device (JBD) performance metrics domain agent (PMDA)
    pmdajson(1) - JSON PMDA
    pmdakernel(1) - operating system kernel performance metrics domain agents
    pmdakvm(1) - Linux virtualization performance metrics domain agent (PMDA)
    pmdaLabel(3) - fill pmdaLabelSet structures with metric labels
    pmdalabel(3) - fill pmdaLabelSet structures with metric labels
    pmdalibvirt(1) - libvirt PMDA
    pmdalinux(1) - operating system kernel performance metrics domain agents
    pmdalio(1) - Linux LIO subsystem PMDA
    pmdalmsensors(1) - Linux hardware monitoring performance metrics domain agent (PMDA)
    pmdalmsensors.python(1) - Linux hardware monitoring performance metrics domain agent (PMDA)
    pmdalogger(1) - log file performance metrics domain agent (PMDA)
    pmdalustre(1) - lustre filesystem statistics performance metrics domain agent (PMDA)
    pmdalustrecomm(1) - Lustre filesystem comms performance metrics domain agent (PMDA)
    pmdamailq(1) - mail queue performance metrics domain agent (PMDA)
    pmdaMain(3) - generic PDU processing for a PMDA
    pmdamain(3) - generic PDU processing for a PMDA
    pmdamemcache(1) - memcached performance metrics domain agent (PMDA)
    pmdamic(1) - MIC card PMDA
    pmdammv(1) - memory mapped values performance metrics domain agent (PMDA)
    pmdamounts(1) - filesystem mounts performance metrics domain agent (PMDA)
    pmdamysql(1) - MySQL and MariaDB database PMDA
    pmdaName(3) - translate a PMID to a set of dynamic performance metric names
    pmdaname(3) - translate a PMID to a set of dynamic performance metric names
    pmdanetbsd(1) - operating system kernel performance metrics domain agents
    pmdanetfilter(1) - Linux netfilter IP connection tracking performance metrics domain agent (PMDA)
    pmdanfsclient(1) - NFS client statistics performance metrics domain agent (PMDA)
    pmdanginx(1) - nginx performance metrics domain agent (PMDA)
    pmdanutcracker(1) - NutCracker performance metrics domain agent (PMDA)
    pmdanvidia(1) - nvidia gpu metrics domain agent (PMDA)
    pmdaOpenHelp(3) - help text support for a PMDA
    pmdaOpenLog(3) - redirect stderr to a logfile
    pmdaopenlog(3) - redirect stderr to a logfile
    pmdaoracle(1) - Oracle database PMDA
    pmdapapi(1) - papi performance metrics domain agent (PMDA)
    pmdaperfevent(1) - hardware performance counter performance metrics domain agent (PMDA)
    pmdapipe(1) - command output capture performance metrics domain agent (PMDA)
    pmdaPMID(3) - translate a dynamic performance metric name into a PMID
    pmdapmid(3) - translate a dynamic performance metric name into a PMID
    pmdapostfix(1) - Postfix performance metrics domain agent (PMDA)
    pmdapostgresql(1) - PostgreSQL database PMDA
    pmdaproc(1) - process performance metrics domain agent (PMDA)
    pmdaProfile(3) - update instance profile for PMDA in preparation for the next fetch from PMCD
    pmdaprofile(3) - update instance profile for PMDA in preparation for the next fetch from PMCD
    pmdaprometheus(1) - Prometheus PMDA
    pmdaredis(1) - Redis performance metrics domain agent (PMDA)
    pmdaRehash(3) - initialize a PMDA
    pmdaroomtemp(1) - room temperature performance metrics domain agent (PMDA)
    pmdaroot(1) - a privileged PMCD helper performance metrics domain agent
    pmdaRootConnect(3) - privileged PCP collector services
    pmdarootconnect(3) - privileged PCP collector services
    pmdaRootContainerCGroupName(3) - privileged PCP collector services
    pmdaRootContainerHostName(3) - privileged PCP collector services
    pmdaRootContainerProcessID(3) - privileged PCP collector services
    pmdaRootProcessStart(3) - privileged PCP collector services
    pmdaRootProcessTerminate(3) - privileged PCP collector services
    pmdaRootProcessWait(3) - privileged PCP collector services
    pmdaRootShutdown(3) - privileged PCP collector services
    pmdarpm(1) - RPM packages performance metrics domain agent (PMDA)
    pmdarsyslog(1) - rsyslog (reliable and extended syslog) PMDA
    pmdasample(1) - sample performance metrics domain agent (PMDA)
    pmdasenderror(3) - pmdaSendError
    pmdasendmail(1) - sendmail performance metrics domain agent (PMDA)
    pmdaSetCheckCallBack(3) - generic PDU processing for a PMDA
    pmdaSetCommFlags(3) - initialize a PMDA
    pmdaSetDoneCallBack(3) - generic PDU processing for a PMDA
    pmdaSetEndContextCallBack(3) - generic PDU processing for a PMDA
    pmdaSetFetchCallBack(3) - fill a pmResult structure with the requested metric values
    pmdaSetFlags(3) - initialize a PMDA
    pmdaSetLabelCallBack(3) - fill pmdaLabelSet structures with metric labels
    pmdaSetResultCallBack(3) - generic PDU processing for a PMDA
    pmdashping(1) - "shell-ping" performance metrics domain agent
    pmdasimple(1) - simple performance metrics domain agent (PMDA)
    pmdaslurm(1) - SLURM statistics performance metrics domain agent (PMDA)
    pmdasmart(1) - S.M.A.R.T Data PMDA
    pmdasolaris(1) - operating system kernel performance metrics domain agents
    pmdaStore(3) - store a value into a metric for a PMDA
    pmdastore(3) - store a value into a metric for a PMDA
    pmdasummary(1) - summary performance metrics domain agent (PMDA)
    pmdasystemd(1) - systemd performance metrics domain agent (PMDA)
    pmdate(1) - display an offset date
    pmdaText(3) - extract metric help text for a PMDA
    pmdatext(3) - extract metric help text for a PMDA
    pmdatrace(1) - application-level transaction performance metrics domain agent
    pmdatrace(3) - application-level performance instrumentation services
    pmdatrivial(1) - trivial performance metrics domain agent (PMDA)
    pmdatxmon(1) - txmon performance metrics domain agent (PMDA)
    pmdaunbound(1) - Unbound resolver PMDA
    pmdaweblog(1) - performance metrics domain agent (PMDA) for Web server logs
    pmdawindows(1) - operating system kernel performance metrics domain agents
    pmdaxfs(1) - XFS filesystem performance metrics domain agent (PMDA)
    pmdazimbra(1) - Zimbra Collaboration Suite (ZCS) PMDA
    pmdazswap(1) - zswap (compressed swap) PMDA
    pmdbg(1) - report Performance Co-Pilot debug options
    pmDelProfile(3) - delete instance(s) from the current PMAPI instance profile
    pmdelprofile(3) - delete instance(s) from the current PMAPI instance profile
    pmDerivedErrStr(3) - return error message from failure to parse derived metric definition
    pmderivederrstr(3) - return error message from failure to parse derived metric definition
    pmDestroyContext(3) - destroy a PMAPI context
    pmdestroycontext(3) - destroy a PMAPI context
    pmDestroyFetchGroup(3) - simplified performance metrics value fetch and conversion
    pmdiff(1) - compares archives and report significant differences
    pmDiscoverServices(3) - discover PCP services on the network
    pmdiscoverservices(3) - discover PCP services on the network
    pmdumplog(1) - dump internal details of a performance metrics archive log
    pmdumptext(1) - dump performance metrics to an ASCII table
    pmDupContext(3) - duplicate a PMAPI context
    pmdupcontext(3) - duplicate a PMAPI context
    pmerr(1) - translate Performance Co-Pilot error codes into error messages
    pmErrStr(3) - convert a PMAPI error code into a string
    pmerrstr(3) - convert a PMAPI error code into a string
    pmErrStr_r(3) - convert a PMAPI error code into a string
    pmevent(1) - arbitrary performance metrics value dumper
    pmEventFlagsStr(3) - convert an event record flags value into a string
    pmeventflagsstr(3) - convert an event record flags value into a string
    pmEventFlagsStr_r(3) - convert an event record flags value into a string
    pmExtendFetchGroup_event(3) - simplified performance metrics value fetch and conversion
    pmExtendFetchGroup_indom(3) - simplified performance metrics value fetch and conversion
    pmExtendFetchGroup_item(3) - simplified performance metrics value fetch and conversion
    pmExtendFetchGroup_timestamp(3) - simplified performance metrics value fetch and conversion
    pmExtractValue(3) - extract a performance metric value from a pmResult structure
    pmextractvalue(3) - extract a performance metric value from a pmResult structure
    pmfault(3) - Fault Injection Infrastracture for QA
    PM_FAULT_CHECK(3) - Fault Injection Infrastracture for QA
    PM_FAULT_CLEAR(3) - Fault Injection Infrastracture for QA
    __pmFaultInject(3) - Fault Injection Infrastracture for QA
    PM_FAULT_POINT(3) - Fault Injection Infrastracture for QA
    PM_FAULT_RETURN(3) - Fault Injection Infrastracture for QA
    __pmFaultSummary(3) - Fault Injection Infrastracture for QA
    __pmFdLookupIPC(3) - IPC version infrastructure support
    pmFetch(3) - get performance metric values
    pmfetch(3) - get performance metric values
    pmFetchArchive(3) - get performance metrics directly from a set if archive logs
    pmfetcharchive(3) - get performance metrics directly from a set if archive logs
    pmFetchGroup(3) - simplified performance metrics value fetch and conversion
    pmfetchgroup(3) - simplified performance metrics value fetch and conversion
    pmfind(1) - find PCP services on the network
    pmflush(3) - print formatted output in a window or to standard error
    __pmFreeAttrsSpec(3) - host and attributes specification parser
    pmFreeEventResult(3) - release storage allocated for unpacked event records
    pmfreeeventresult(3) - release storage allocated for unpacked event records
    pmFreeHighResEventResult(3) - release storage allocated for unpacked event records
    __pmFreeHostAttrsSpec(3) - host and attributes specification parser
    __pmFreeHostSpec(3) - uniform host specification parser
    pmFreeLabelSets(3) - release storage allocated for performance metric labels
    pmfreelabelsets(3) - release storage allocated for performance metric labels
    pmFreeMetricSpec(3) - uniform metric specification parser
    pmFreeOptions(3) - command line handling for PMAPI tools
    pmfreeprofile(3) - free a PMAPI instance profile
    __pmFreeProfile(3) - free a PMAPI instance profile
    pmFreeResult(3) - release storage allocated for performance metrics values
    pmfreeresult(3) - release storage allocated for performance metrics values
    pmgenmap(1) - generate C code to simplify handling of performance metrics
    pmGetAPIConfig(3) - return values for Performance Co-Pilot configuration variables
    pmGetArchiveEnd(3) - locate logical end of file for a set of archive logs
    pmgetarchiveend(3) - locate logical end of file for a set of archive logs
    pmGetArchiveLabel(3) - fetch the label record from a set of performance metrics archive logs
    pmgetarchivelabel(3) - fetch the label record from a set of performance metrics archive logs
    pmGetChildren(3) - return the descendent nodes of a PMNS node
    pmgetchildren(3) - return the descendent nodes of a PMNS node
    pmGetChildrenStatus(3) - return the descendent nodes of a PMNS node and their respective status
    pmgetchildrenstatus(3) - return the descendent nodes of a PMNS node and their respective status
    pmGetClusterLabels(3) - retrieve labels associated with performance metric values
    pmGetConfig(3) - return values for Performance Co-Pilot configuration variables
    pmgetconfig(3) - return values for Performance Co-Pilot configuration variables
    pmGetContextHostName(3) - return the hostname associated with a Performance Co-Pilot context
    pmgetcontexthostname(3) - return the hostname associated with a Performance Co-Pilot context
    pmGetContextHostName_r(3) - return the hostname associated with a Performance Co-Pilot context
    pmGetContextLabels(3) - retrieve labels associated with performance metric values
    pmGetContextOptions(3) - command line handling for PMAPI tools
    pmGetDomainLabels(3) - retrieve labels associated with performance metric values
    pmGetFetchGroupContext(3) - simplified performance metrics value fetch and conversion
    pmGetInDom(3) - get instance identifiers for a performance metrics instance domain
    pmgetindom(3) - get instance identifiers for a performance metrics instance domain
    pmGetInDomArchive(3) - get instance identifiers for a performance metrics instance domain
    pmgetindomarchive(3) - get instance identifiers for a performance metrics instance domain
    pmGetInDomLabels(3) - retrieve labels associated with performance metric values
    pmGetInstancesLabels(3) - retrieve labels associated with performance metric values
    pmGetItemLabels(3) - retrieve labels associated with performance metric values
    pmgetopt(1) - Performance Co-Pilot shell script option parser
    pmGetOptionalConfig(3) - return values for Performance Co-Pilot configuration variables
    pmGetOptions(3) - command line handling for PMAPI tools
    pmgetoptions(3) - command line handling for PMAPI tools
    pmgetopt_r(3) - command line handling for PMAPI tools
    pmGetPMNSLocation(3) - determine the location of the currently used PMNS
    pmgetpmnslocation(3) - determine the location of the currently used PMNS
    pmGetProgname(3) - application name services
    pmGetUsername(3) - fetch special PCP username
    pmgetusername(3) - fetch special PCP username
    pmGetVersion(3) - fetch installed PCP version number
    pmgetversion(3) - fetch installed PCP version number
    pmhostname(1) - report hostname
    pmhttpClientFetch(3) - simple HTTP client interfaces
    pmhttpFreeClient(3) - simple HTTP client interfaces
    pmhttpNewClient(3) - simple HTTP client interfaces
    pmhttpnewclient(3) - simple HTTP client interfaces
    pmiAddInstance(3) - add an element to an instance domain in a LOGIMPORT context
    pmiaddinstance(3) - add an element to an instance domain in a LOGIMPORT context
    pmiAddMetric(3) - add a new metric definition to a LOGIMPORT context
    pmiaddmetric(3) - add a new metric definition to a LOGIMPORT context
    pmID_build(3) - helper methods for manipulating PMIDs
    pmID_cluster(3) - helper methods for manipulating PMIDs
    pmID_domain(3) - helper methods for manipulating PMIDs
    pmid_helper(3) - helper methods for manipulating PMIDs
    pmID_item(3) - helper methods for manipulating PMIDs
    pmIDStr(3) - convert a performance metric identifier into a string
    pmidstr(3) - convert a performance metric identifier into a string
    pmIDStr_r(3) - convert a performance metric identifier into a string
    pmie(1) - inference engine for performance metrics
    pmie2col(1) - convert pmie output to multi-column format
    pmie_check(1) - administration of the Performance Co-Pilot inference engine
    pmieconf(1) - display and set configurable pmie rule variables
    pmieconf(5) - generalized pmie rules and customizations
    pmie_daily(1) - administration of the Performance Co-Pilot inference engine
    pmiEnd(3) - finish up a LOGIMPORT archive
    pmiend(3) - finish up a LOGIMPORT archive
    pmiErrStr(3) - convert a LOGIMPORT error code into a string
    pmierrstr(3) - convert a LOGIMPORT error code into a string
    pmiestatus(1) - display information from pmie stats file
    pmiGetHandle(3) - define a handle for a metric-instance pair
    pmigethandle(3) - define a handle for a metric-instance pair
    pmiID(3) - construct core metric data structures
    pmiInDom(3) - construct core metric data structures
    pmInDom_build(3) - helper methods for manipulating instance domain identifiers
    pmInDom_domain(3) - helper methods for manipulating instance domain identifiers
    pmindom_helper(3) - helper methods for manipulating instance domain identifiers
    pmInDom_serial(3) - helper methods for manipulating instance domain identifiers
    pmInDomStr(3) - convert a performance metric instance domain identifier into a string
    pmindomstr(3) - convert a performance metric instance domain identifier into a string
    pmInDomStr_r(3) - convert a performance metric instance domain identifier into a string
    pminfo(1) - display information about performance metrics
    pmiostat(1) - performance metrics i/o statistics tool
    pmiPutMark(3) - write a <mark> record to a PCP archive
    pmiputmark(3) - write a <mark> record to a PCP archive
    pmiPutResult(3) - add a data record to a LOGIMPORT archive
    pmiputresult(3) - add a data record to a LOGIMPORT archive
    pmiPutValue(3) - add a value for a metric-instance pair
    pmiputvalue(3) - add a value for a metric-instance pair
    pmiPutValueHandle(3) - add a value for a metric-instance pair via a handle
    pmiputvaluehandle(3) - add a value for a metric-instance pair via a handle
    pmiSetHostname(3) - set the source host name for a LOGIMPORT archive
    pmisethostname(3) - set the source host name for a LOGIMPORT archive
    pmiSetTimezone(3) - set the source timezone for a LOGIMPORT archive
    pmisettimezone(3) - set the source timezone for a LOGIMPORT archive
    pmiStart(3) - establish a new LOGIMPORT context
    pmistart(3) - establish a new LOGIMPORT context
    pmiUnits(3) - construct core metric data structures
    pmiunits(3) - construct core metric data structures
    pmiUseContext(3) - change LOGIMPORT context
    pmiusecontext(3) - change LOGIMPORT context
    pmiWrite(3) - flush data to a LOGIMPORT archive
    pmiwrite(3) - flush data to a LOGIMPORT archive
    pmjson(1) - Performance Co-Pilot JSON dumping utility
    pmjsonGet(3) - JSON string helpers and metrics extraction
    pmjsonget(3) - JSON string helpers and metrics extraction
    pmjsonInit(3) - JSON string helpers and metrics extraction
    pmjsonInitIndom(3) - JSON string helpers and metrics extraction
    pmjsonPrint(3) - JSON string helpers and metrics extraction
    pmlc(1) - configure active Performance Co-Pilot pmlogger(s) interactively
    pmLoadASCIINameSpace(3) - establish a local PMNS for an application
    pmloadasciinamespace(3) - establish a local PMNS for an application
    pmLoadDerivedConfig(3) - load derived metric definitions from files
    pmloadderivedconfig(3) - load derived metric definitions from files
    pmLoadNameSpace(3) - load a local PMNS for an application
    pmloadnamespace(3) - load a local PMNS for an application
    __pmLocalPMDA(3) - change the table of DSO PMDAs for PM_CONTEXT_LOCAL contexts
    __pmlocalpmda(3) - change the table of DSO PMDAs for PM_CONTEXT_LOCAL contexts
    pmLocaltime(3) - convert the date and time for a reporting timezone
    pmlocaltime(3) - convert the date and time for a reporting timezone
    pmlock(1) - simple file-based mutex
    pmlogcheck(1) - checks for invalid data in a PCP archive
    pmlogconf(1) - create/edit a pmlogger configuration file
    pmlogextract(1) - reduce, extract, concatenate and merge Performance Co-Pilot archives
    pmlogger(1) - create archive log for performance metrics
    pmlogger_check(1) - administration of Performance Co-Pilot archive log files
    pmlogger_daily(1) - administration of Performance Co-Pilot archive log files
    pmlogger_daily_report(1) - write Performance Co-Pilot daily summary reports
    pmlogger_merge(1) - helper script to merge Performance Co-Pilot archives
    pmlogger_rewrite(1) - helper script to rewrite Performance Co-Pilot archives
    pmloglabel(1) - check and repair a performance metrics archive label
    pmlogmv(1) - move (rename) Performance Co-Pilot archive files
    pmlogreduce(1) - temporal reduction of Performance Co-Pilot archives
    pmlogrewrite(1) - rewrite Performance Co-Pilot archives
    pmlogsize(1) - report sizes for parts of PCP archive(s)
    pmlogsummary(1) - calculate averages of metrics stored in a set of PCP archives
    pmLookupDesc(3) - obtain a description for a performance metric
    pmlookupdesc(3) - obtain a description for a performance metric
    pmLookupInDom(3) - translate an instance name into an instance identifier
    pmlookupindom(3) - translate an instance name into an instance identifier
    pmLookupInDomArchive(3) - translate an instance name into an instance identifier
    pmlookupindomarchive(3) - translate an instance name into an instance identifier
    pmLookupInDomText(3) - return text describing a performance metrics instance domain
    pmlookupindomtext(3) - return text describing a performance metrics instance domain
    __pmLookupIPC(3) - IPC version infrastructure support
    __pmlookupipc(3) - IPC version infrastructure support
    pmLookupLabels(3) - retrieve labels associated with performance metric values
    pmlookuplabels(3) - retrieve labels associated with performance metric values
    pmLookupName(3) - translate performance metric names into PMIDs
    pmlookupname(3) - translate performance metric names into PMIDs
    pmLookupText(3) - return text describing a performance metric
    pmlookuptext(3) - return text describing a performance metric
    pmMergeLabels(3) - merge sets of performance metric labels
    pmmergelabels(3) - merge sets of performance metric labels
    pmMergeLabelSets(3) - merge sets of performance metric labels
    pmmessage(1) - general purpose dialog box
    pmmgr(1) - pcp daemon manager
    __pmMktime(3) - convert a tm structure to a calendar time
    __pmmktime(3) - convert a tm structure to a calendar time
    pmNameAll(3) - translate a PMID to a set of performance metric names
    pmnameall(3) - translate a PMID to a set of performance metric names
    pmNameID(3) - translate a PMID to a performance metric name
    pmnameid(3) - translate a PMID to a performance metric name
    pmNameInDom(3) - translate an instance identifier into an instance name
    pmnameindom(3) - translate an instance identifier into an instance name
    pmNameInDomArchive(3) - translate an instance identifier into an instance name
    pmnameindomarchive(3) - translate an instance identifier into an instance name
    pmNewContext(3) - establish a new PMAPI context
    pmnewcontext(3) - establish a new PMAPI context
    pmNewContextZone(3) - establish a reporting timezone based on a PMAPI context
    pmnewcontextzone(3) - establish a reporting timezone based on a PMAPI context
    pmnewlog(1) - stop and restart archive logging for PCP performance metrics
    pmNewZone(3) - establish a reporting timezone
    pmnewzone(3) - establish a reporting timezone
    pmNoMem(3) - report out of memory conditions
    pmnomem(3) - report out of memory conditions
    pmNotifyErr(3) - standard handling of error messages
    pmnotifyerr(3) - standard handling of error messages
    pmns(5) - the performance metrics name space
    pmnsadd(1) - add new names to the Performance Co-Pilot PMNS
    pmnscomp(1) - compile an ASCII performance metrics namespace into binary format.
    pmnsdel(1) - delete a subtree of names from the Performance Co-Pilot PMNS
    pmnsmerge(1) - merge multiple versions of a Performance Co-Pilot PMNS
    pmNumberStr(3) - fixed width output format for numbers
    pmnumberstr(3) - fixed width output format for numbers
    pmNumberStr_r(3) - fixed width output format for numbers
    pmOpenLog(3) - create a log file for diagnostics and debug output
    pmopenlog(3) - create a log file for diagnostics and debug output
    __pmOverrideLastFd(3) - IPC version infrastructure support
    __pmParseCtime(3) - convert ctime(3) string to tm structure
    __pmparsectime(3) - convert ctime(3) string to tm structure
    pmparsedebug(3) - manipulate old-style PCP debugging control bit-fields
    __pmParseDebug(3) - manipulate old-style PCP debugging control bit-fields
    pmparsehostattrsspec(3) - host and attributes specification parser
    __pmParseHostAttrsSpec(3) - host and attributes specification parser
    pmparsehostspec(3) - uniform host specification parser
    __pmParseHostSpec(3) - uniform host specification parser
    pmParseInterval(3) - convert interval string to timeval structure
    pmparseinterval(3) - convert interval string to timeval structure
    pmParseMetricSpec(3) - uniform metric specification parser
    pmparsemetricspec(3) - uniform metric specification parser
    __pmParseTime(3) - parse time point specification
    __pmparsetime(3) - parse time point specification
    pmParseTimeWindow(3) - parse time window command line arguments
    pmparsetimewindow(3) - parse time window command line arguments
    pmParseUnitsStr(3) - parse units specification
    pmparseunitsstr(3) - parse units specification
    pmPathSeparator(3) - return the filesystem path separator character
    pmpathseparator(3) - return the filesystem path separator character
    pmpause(1) - portable subsecond-capable sleep
    pmpost(1) - append messages to the Performance Co-Pilot notice board
    pmPrintDesc(3) - print a metric descriptor
    pmprintdesc(3) - print a metric descriptor
    pmprintf(3) - print formatted output in a window or to standard error
    pmPrintHighResStamp(3) - helper routines for time stored as a struct timeval
    __pmPrintIPC(3) - IPC version infrastructure support
    pmPrintLabelSets(3) - print an array of label sets
    pmprintlabelsets(3) - print an array of label sets
    pmPrintStamp(3) - helper routines for time stored as a struct timeval
    pmPrintValue(3) - print a performance metric value
    pmprintvalue(3) - print a performance metric value
    pmprobe(1) - lightweight probe for performance metrics
    __pmProcessAddArg(3) - process execution support
    __pmProcessClosePipe(3) - support for process execution at the end of a pipe
    __pmProcessExec(3) - process execution support
    __pmprocessexec(3) - process execution support
    __pmProcessPipe(3) - support for process execution at the end of a pipe
    __pmprocesspipe(3) - support for process execution at the end of a pipe
    __pmProcessUnpickArgs(3) - process execution support
    pmproxy(1) - proxy for performance metrics collector daemon
    pmpython(1) - run a python script using a preferred python variant
    pmquery(1) - general purpose dialog box
    pmReconnectContext(3) - reconnect to a PMAPI context
    pmreconnectcontext(3) - reconnect to a PMAPI context
    pmRecordAddHost(3) - record mode support for PMAPI clients
    pmRecordControl(3) - record mode support for PMAPI clients
    pmRecordSetup(3) - record mode support for PMAPI clients
    pmRegisterDerived(3) - register a derived metric name and definition
    pmregisterderived(3) - register a derived metric name and definition
    pmRegisterDerivedMetric(3) - register a derived metric name and definition
    pmrep(1) - performance metrics reporter
    pmrep.conf(5) - pmrep configuration file
    __pmResetIPC(3) - IPC version infrastructure support
    pmSemStr(3) - convert a performance metric semantic into a string
    pmsemstr(3) - convert a performance metric semantic into a string
    pmSemStr_r(3) - convert a performance metric semantic into a string
    pmSetDebug(3) - manipulate PCP debugging control options
    pmsetdebug(3) - manipulate PCP debugging control options
    __pmSetDebugBits(3) - manipulate old-style PCP debugging control bit-fields
    pmSetMode(3) - set collection time parameters for the current PMAPI context
    pmsetmode(3) - set collection time parameters for the current PMAPI context
    pmSetProcessIdentity(3) - set process user and group id
    pmsetprocessidentity(3) - set process user and group id
    pmSetProgname(3) - application name services
    pmsetprogname(3) - application name services
    pmsignal(1) - send a signal to one or more processes
    pmsleep(1) - portable subsecond-capable sleep
    pmsnap(1) - generate performance summary snapshot images
    pmsocks(1) - shell wrapper for performance monitoring across firewalls
    pmSortInstances(3) - sort performance metric values on instance identifier
    pmsortinstances(3) - sort performance metric values on instance identifier
    pmSpecLocalPMDA(3) - process command-line argument for the table of DSO PMDAs
    pmspeclocalpmda(3) - process command-line argument for the table of DSO PMDAs
    pmsprintf(3) - formatted string conversion
    pmstat(1) - high-level system performance overview
    pmstore(1) - modify performance metric values
    pmStore(3) - modify values of performance metrics
    pmstore(3) - modify values of performance metrics
    pmSyslog(3) - standard handling of error messages
    pmtime(1) - time control server for Performance Co-Pilot
    pmtime(3) - time control functions for synchronizing the archive position and update interval between one or more applications
    pmTimeConnect(3) - time control functions for synchronizing the archive position and update interval between one or more applications
    pmTimeDisconnect(3) - time control functions for synchronizing the archive position and update interval between one or more applications
    pmTimeRecv(3) - time control functions for synchronizing the archive position and update interval between one or more applications
    pmTimeSendAck(3) - time control functions for synchronizing the archive position and update interval between one or more applications
    pmTimeShowDialog(3) - time control functions for synchronizing the archive position and update interval between one or more applications
    pmtimeval(3) - helper routines for time stored as a struct timeval
    pmtimevalAdd(3) - helper routines for time stored as a struct timeval
    pmtimevalDec(3) - helper routines for time stored as a struct timeval
    pmtimevalFromReal(3) - helper routines for time stored as a struct timeval
    pmtimevalInc(3) - helper routines for time stored as a struct timeval
    pmtimevalNow(3) - helper routines for time stored as a struct timeval
    pmtimevalSub(3) - helper routines for time stored as a struct timeval
    pmtimevalToReal(3) - helper routines for time stored as a struct timeval
    pmtrace(1) - command line performance instrumentation
    pmtraceabort(3) - application-level performance instrumentation services
    pmtracebegin(3) - application-level performance instrumentation services
    pmtracecounter(3) - application-level performance instrumentation services
    pmtraceend(3) - application-level performance instrumentation services
    pmtraceerrstr(3) - application-level performance instrumentation services
    pmtraceobs(3) - application-level performance instrumentation services
    pmtracepoint(3) - application-level performance instrumentation services
    pmtracestate(3) - application-level performance instrumentation services
    pmTraversePMNS(3) - traverse the performance metrics name space
    pmtraversepmns(3) - traverse the performance metrics name space
    pmTraversePMNS_r(3) - traverse the performance metrics name space
    pmTrimNameSpace(3) - prune a performance metrics name space
    pmtrimnamespace(3) - prune a performance metrics name space
    pmTypeStr(3) - convert a performance metric type into a string
    pmtypestr(3) - convert a performance metric type into a string
    pmTypeStr_r(3) - convert a performance metric type into a string
    pmUnitsStr(3) - convert a performance metric's units into a string
    pmunitsstr(3) - convert a performance metric's units into a string
    pmUnitsStr_r(3) - convert a performance metric's units into a string
    pmUnloadNameSpace(3) - unload a local performance metrics name space for an application
    pmunloadnamespace(3) - unload a local performance metrics name space for an application
    pmUnpackEventRecords(3) - unpack event records
    pmunpackeventrecords(3) - unpack event records
    pmUnpackHighResEventRecords(3) - unpack event records
    __pmUnparseHostAttrsSpec(3) - host and attributes specification parser
    __pmUnparseHostSpec(3) - uniform host specification parser
    pmUsageMessage(3) - command line handling for PMAPI tools
    pmUseContext(3) - change current PMAPI context
    pmusecontext(3) - change current PMAPI context
    pmUseZone(3) - re-establish a reporting timezone
    pmusezone(3) - re-establish a reporting timezone
    pmval(1) - arbitrary performance metrics value dumper
    pmview(1) - performance metrics 3D visualization back-end
    pmview(5) - configuration file format for performance
    PMWEBAPI(3) - introduction to the Performance Metrics Web Application Programming Interface
    pmwebapi(3) - introduction to the Performance Metrics Web Application Programming Interface
    pmwebd(1) - web access to PCP
    pmWhichContext(3) - identify the current PMAPI context
    pmwhichcontext(3) - identify the current PMAPI context
    pmWhichZone(3) - return current reporting timezone
    pmwhichzone(3) - return current reporting timezone
    pnoutrefresh(3x) - create and display curses pads
    police(8) - policing action
    poll(2) - wait for some event on a file descriptor
    poll(3p) - input/output multiplexing
    poll.h(0p) - definitions for the poll() function
    popen(3) - pipe stream to or from a process
    popen(3p) - initiate pipe streams to or from a process
    port(4) - system memory, kernel memory and system ports
    pos_form_cursor(3x) - position a form window cursor
    posix_fadvise(2) - predeclare an access pattern for file data
    posix_fadvise(3p) - file advisory information (ADVANCED REALTIME)
    posix_fallocate(3) - allocate file space
    posix_fallocate(3p) - file space control (ADVANCED REALTIME)
    posix_madvise(3) - give advice about patterns of memory usage
    posix_madvise(3p) - memory advisory information and alignment control (ADVANCED REALTIME)
    posix_memalign(3) - allocate aligned memory
    posix_memalign(3p) - aligned memory allocation (ADVANCED REALTIME)
    posix_mem_offset(3p) - find offset and length of a mapped typed memory block (ADVANCED REALTIME)
    posix_openpt(3) - open a pseudoterminal device
    posix_openpt(3p) - terminal device
    posixoptions(7) - optional parts of the POSIX standard
    posix_spawn(3) - spawn a process
    posix_spawn(3p) - spawn a process (ADVANCED REALTIME)
    posix_spawnattr_destroy(3p) - destroy and initialize spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_getflags(3p) - flags attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_getpgroup(3p) - pgroup attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_getschedparam(3p) - schedparam attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_getschedpolicy(3p) - schedpolicy attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_getsigdefault(3p) - sigdefault attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_getsigmask(3p) - sigmask attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_init(3p) - initialize the spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_setflags(3p) - flags attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_setpgroup(3p) - pgroup attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_setschedparam(3p) - schedparam attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_setschedpolicy(3p) - schedpolicy attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_setsigdefault(3p) - sigdefault attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawnattr_setsigmask(3p) - sigmask attribute of a spawn attributes object (ADVANCED REALTIME)
    posix_spawn_file_actions_addclose(3p) - add close or open action to spawn file actions object (ADVANCED REALTIME)
    posix_spawn_file_actions_adddup2(3p) - add dup2 action to spawn file actions object (ADVANCED REALTIME)
    posix_spawn_file_actions_addopen(3p) - add open action to spawn file actions object (ADVANCED REALTIME)
    posix_spawn_file_actions_destroy(3p) - destroy and initialize spawn file actions object (ADVANCED REALTIME)
    posix_spawn_file_actions_init(3p) - destroy and initialize spawn file actions object (ADVANCED REALTIME)
    posix_spawnp(3) - spawn a process
    posix_spawnp(3p) - spawn a process (ADVANCED REALTIME)
    posix_trace_attr_destroy(3p) - destroy and initialize the trace stream attributes object (TRACING)
    posix_trace_attr_getclockres(3p) - retrieve and set information about a trace stream (TRACING)
    posix_trace_attr_getcreatetime(3p) - retrieve and set information about a trace stream (TRACING)
    posix_trace_attr_getgenversion(3p) - retrieve and set information about a trace stream (TRACING)
    posix_trace_attr_getinherited(3p) - retrieve and set the behavior of a trace stream (TRACING)
    posix_trace_attr_getlogfullpolicy(3p) - retrieve and set the behavior of a trace stream (TRACING)
    posix_trace_attr_getlogsize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_attr_getmaxdatasize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_attr_getmaxsystemeventsize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_attr_getmaxusereventsize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_attr_getname(3p) - retrieve and set information about a trace stream (TRACING)
    posix_trace_attr_getstreamfullpolicy(3p) - retrieve and set the behavior of a trace stream (TRACING)
    posix_trace_attr_getstreamsize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_attr_init(3p) - initialize the trace stream attributes object (TRACING)
    posix_trace_attr_setinherited(3p) - retrieve and set the behavior of a trace stream (TRACING)
    posix_trace_attr_setlogfullpolicy(3p) - retrieve and set the behavior of a trace stream (TRACING)
    posix_trace_attr_setlogsize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_attr_setmaxdatasize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_attr_setname(3p) - retrieve and set information about a trace stream (TRACING)
    posix_trace_attr_setstreamfullpolicy(3p) - retrieve and set the behavior of a trace stream (TRACING)
    posix_trace_attr_setstreamsize(3p) - retrieve and set trace stream size attributes (TRACING)
    posix_trace_clear(3p) - clear trace stream and trace log (TRACING)
    posix_trace_close(3p) - trace log management (TRACING)
    posix_trace_create(3p) - trace stream initialization, flush, and shutdown from a process (TRACING)
    posix_trace_create_withlog(3p) - trace stream initialization, flush, and shutdown from a process (TRACING)
    posix_trace_event(3p) - trace functions for instrumenting application code (TRACING)
    posix_trace_eventid_equal(3p) - manipulate the trace event type identifier (TRACING)
    posix_trace_eventid_get_name(3p) - manipulate the trace event type identifier (TRACING)
    posix_trace_eventid_open(3p) - trace functions for instrumenting application code (TRACING)
    posix_trace_eventset_add(3p) - manipulate trace event type sets (TRACING)
    posix_trace_eventset_del(3p) - manipulate trace event type sets (TRACING)
    posix_trace_eventset_empty(3p) - manipulate trace event type sets (TRACING)
    posix_trace_eventset_fill(3p) - manipulate trace event type sets (TRACING)
    posix_trace_eventset_ismember(3p) - manipulate trace event type sets (TRACING)
    posix_trace_eventtypelist_getnext_id(3p) - iterate over a mapping of trace event types (TRACING)
    posix_trace_eventtypelist_rewind(3p) - iterate over a mapping of trace event types (TRACING)
    posix_trace_flush(3p) - trace stream flush from a process (TRACING)
    posix_trace_get_attr(3p) - retrieve the trace attributes or trace status (TRACING)
    posix_trace_get_filter(3p) - retrieve and set the filter of an initialized trace stream (TRACING)
    posix_trace_getnext_event(3p) - retrieve a trace event (TRACING)
    posix_trace_get_status(3p) - retrieve the trace status (TRACING)
    posix_trace_open(3p) - trace log management (TRACING)
    posix_trace_rewind(3p) - trace log management (TRACING)
    posix_trace_set_filter(3p) - set filter of an initialized trace stream (TRACING)
    posix_trace_shutdown(3p) - trace stream shutdown from a process (TRACING)
    posix_trace_start(3p) - trace start and stop (TRACING)
    posix_trace_stop(3p) - trace start and stop (TRACING)
    posix_trace_timedgetnext_event(3p) - retrieve a trace event (TRACING)
    posix_trace_trid_eventid_open(3p) - open a trace event type identifier (TRACING)
    posix_trace_trygetnext_event(3p) - retrieve a trace event (TRACING)
    posix_typed_mem_get_info(3p) - query typed memory information (ADVANCED REALTIME)
    posix_typed_mem_open(3p) - open a typed memory object (ADVANCED REALTIME)
    pos_menu_cursor(3x) - position a menu's cursor
    post_form(3x) - write or erase forms from associated subwindows
    postgres_pg_stat_tables.10.3(1) -
    postgres_pg_stat_tables.9.4(5) -
    postgres_pg_stat_tables.9.5(4) -
    postgres_pg_stat_tables.9.6(5) -
    postgres_pg_stat_tables.9.6(7) -
    post_menu(3x) - write or erase menus from associated subwindows
    pow(3) - power functions
    pow(3p) - power function
    pow10(3) - base-10 power functions
    pow10f(3) - base-10 power functions
    pow10l(3) - base-10 power functions
    poweroff(8) - Halt, power-off or reboot the machine
    powf(3) - power functions
    powf(3p) - power function
    powl(3) - power functions
    powl(3p) - power function
    __ppc_get_timebase(3) - get the current value
    __ppc_get_timebase_freq(3) - get the current value
    __ppc_mdoio(3) - Hint the processor to release shared resources
    __ppc_mdoom(3) - Hint the processor to release shared resources
    __ppc_set_ppr_low(3) - Set the Program Priority Register
    __ppc_set_ppr_med(3) - Set the Program Priority Register
    __ppc_set_ppr_med_high(3) - Set the Program Priority Register
    __ppc_set_ppr_med_low(3) - Set the Program Priority Register
    __ppc_set_ppr_very_low(3) - Set the Program Priority Register
    __ppc_yield(3) - Hint the processor to release shared resources
    ppdc(1) - cups ppd compiler (deprecated)
    ppdcfile(5) - cups ppd compiler source file format
    ppdhtml(1) - cups html summary generator (deprecated)
    ppdi(1) - import ppd files (deprecated)
    ppdmerge(1) - merge ppd files (deprecated)
    ppdpo(1) - ppd message catalog generator (deprecated)
    ppoll(2) - wait for some event on a file descriptor
    pr(1) - convert text files for printing
    pr(1p) - print files
    prctl(2) - operations on a process
    pread(2) - read from or write to a file descriptor at a given offset
    pread(3p) - read from a file
    pread64(2) - read from or write to a file descriptor at a given offset
    preadv(2) - read or write data into multiple buffers
    preadv2(2) - read or write data into multiple buffers
    preconv(1) - convert encoding of input files to something GNU troff understands
    prefresh(3x) - create and display curses pads
    prelink(8) - prelink ELF shared libraries and binaries to speed up startup time
    print_access_vector(3) - display an access vector in human-readable form.
    printenv(1) - print all or part of environment
    printers.conf(5) - printer configuration file for cups
    printf(1) - format and print data
    printf(1p) - write formatted output
    printf(3) - formatted output conversion
    printf(3p) - print formatted output
    printw(3x) - print formatted output in curses windows
    PRIO(8) - Priority qdisc
    prlimit(1) - get and set process resource limits
    prlimit(2) - get/set resource limits
    prlimit64(2) - get/set resource limits
    proc(5) - process information pseudo-filesystem
    process-keyring(7) - per-process shared keyring
    process_vm_readv(2) - transfer data between process address spaces
    process_vm_writev(2) - transfer data between process address spaces
    procfs(5) - process information pseudo-filesystem
    procps(1) - report a snapshot of the current processes.
    prof(2) - unimplemented system calls
    profil(3) - execution time profile
    profile(5) - Security profile file syntax for Firejail
    program_invocation_name(3) - obtain name used to invoke calling program
    program_invocation_short_name(3) - obtain name used to invoke calling program
    projects(5) - persistent project root definition
    projid(5) - the project name mapping file
    protocols(5) - protocols definition file
    prs(1p) - print an SCCS file (DEVELOPMENT)
    prtstat(1) - print statistics of a process
    ps(1) - report a snapshot of the current processes.
    ps(1p) - report process status
    pscap(8) - a program to see capabilities
    pselect(2) - synchronous I/O multiplexing
    pselect(3p) - synchronous I/O multiplexing
    pselect6(2) - synchronous I/O multiplexing
    psfaddtable(1) - add a Unicode character table to a console font
    psfgettable(1) - extract the embedded Unicode character table from a console font
    psfstriptable(1) - remove the embedded Unicode character table from a console font
    psfxtable(1) - handle Unicode character tables for console fonts
    psiginfo(3) - print signal message
    psiginfo(3p) - print signal information to standard error
    psignal(3) - print signal message
    psignal(3p) - print signal information to standard error
    psktool(1) - GnuTLS PSK tool
    pslog(1) - report current logs path of a process
    pstree(1) - display a tree of processes
    pthread.h(0p) - threads
    pthread_atfork(3) - register fork handlers
    pthread_atfork(3p) - register fork handlers
    pthread_attr_destroy(3) - initialize and destroy thread attributes object
    pthread_attr_destroy(3p) - destroy and initialize the thread attributes object
    pthread_attr_getaffinity_np(3) - set/get CPU affinity attribute in thread attributes object
    pthread_attr_getdetachstate(3) - set/get detach state attribute in thread attributes object
    pthread_attr_getdetachstate(3p) - get and set the detachstate attribute
    pthread_attr_getguardsize(3) - set/get guard size attribute in thread attributes object
    pthread_attr_getguardsize(3p) - get and set the thread guardsize attribute
    pthread_attr_getinheritsched(3) - set/get inherit-scheduler attribute in thread attributes object
    pthread_attr_getinheritsched(3p) - get and set the inheritsched attribute (REALTIME THREADS)
    pthread_attr_getschedparam(3) - set/get scheduling parameter attributes in thread attributes object
    pthread_attr_getschedparam(3p) - get and set the schedparam attribute
    pthread_attr_getschedpolicy(3) - set/get scheduling policy attribute in thread attributes object
    pthread_attr_getschedpolicy(3p) - get and set the schedpolicy attribute (REALTIME THREADS)
    pthread_attr_getscope(3) - set/get contention scope attribute in thread attributes object
    pthread_attr_getscope(3p) - get and set the contentionscope attribute (REALTIME THREADS)
    pthread_attr_getstack(3) - set/get stack attributes in thread attributes object
    pthread_attr_getstack(3p) - get and set stack attributes
    pthread_attr_getstackaddr(3) - set/get stack address attribute in thread attributes object
    pthread_attr_getstacksize(3) - set/get stack size attribute in thread attributes object
    pthread_attr_getstacksize(3p) - get and set the stacksize attribute
    pthread_attr_init(3) - initialize and destroy thread attributes object
    pthread_attr_init(3p) - initialize the thread attributes object
    pthread_attr_setaffinity_np(3) - set/get CPU affinity attribute in thread attributes object
    pthread_attr_setdetachstate(3) - set/get detach state attribute in thread attributes object
    pthread_attr_setdetachstate(3p) - set the detachstate attribute
    pthread_attr_setguardsize(3) - set/get guard size attribute in thread attributes object
    pthread_attr_setguardsize(3p) - set the thread guardsize attribute
    pthread_attr_setinheritsched(3) - set/get inherit-scheduler attribute in thread attributes object
    pthread_attr_setinheritsched(3p) - set the inheritsched attribute (REALTIME THREADS)
    pthread_attr_setschedparam(3) - set/get scheduling parameter attributes in thread attributes object
    pthread_attr_setschedparam(3p) - set the schedparam attribute
    pthread_attr_setschedpolicy(3) - set/get scheduling policy attribute in thread attributes object
    pthread_attr_setschedpolicy(3p) - set the schedpolicy attribute (REALTIME THREADS)
    pthread_attr_setscope(3) - set/get contention scope attribute in thread attributes object
    pthread_attr_setscope(3p) - set the contentionscope attribute (REALTIME THREADS)
    pthread_attr_setstack(3) - set/get stack attributes in thread attributes object
    pthread_attr_setstack(3p) - set the stack attribute
    pthread_attr_setstackaddr(3) - set/get stack address attribute in thread attributes object
    pthread_attr_setstacksize(3) - set/get stack size attribute in thread attributes object
    pthread_attr_setstacksize(3p) - set the stacksize attribute
    pthread_barrierattr_destroy(3p) - destroy and initialize the barrier attributes object
    pthread_barrierattr_getpshared(3p) - shared attribute of the barrier attributes object
    pthread_barrierattr_init(3p) - initialize the barrier attributes object
    pthread_barrierattr_setpshared(3p) - shared attribute of the barrier attributes object
    pthread_barrier_destroy(3p) - destroy and initialize a barrier object
    pthread_barrier_init(3p) - destroy and initialize a barrier object
    pthread_barrier_wait(3p) - synchronize at a barrier
    pthread_cancel(3) - send a cancellation request to a thread
    pthread_cancel(3p) - cancel execution of a thread
    pthread_cleanup_pop(3) - push and pop thread cancellation clean-up handlers
    pthread_cleanup_pop(3p) - establish cancellation handlers
    pthread_cleanup_pop_restore_np(3) - push and pop thread cancellation clean-up handlers while saving cancelability type
    pthread_cleanup_push(3) - push and pop thread cancellation clean-up handlers
    pthread_cleanup_push(3p) - establish cancellation handlers
    pthread_cleanup_push_defer_np(3) - push and pop thread cancellation clean-up handlers while saving cancelability type
    pthread_condattr_destroy(3p) - destroy and initialize the condition variable attributes object
    pthread_condattr_getclock(3p) - get and set the clock selection condition variable attribute
    pthread_condattr_getpshared(3p) - shared condition variable attributes
    pthread_condattr_init(3p) - initialize the condition variable attributes object
    pthread_condattr_setclock(3p) - set the clock selection condition variable attribute
    pthread_condattr_setpshared(3p) - shared condition variable attribute
    pthread_cond_broadcast(3p) - broadcast or signal a condition
    pthread_cond_destroy(3p) - destroy and initialize condition variables
    pthread_cond_init(3p) - destroy and initialize condition variables
    pthread_cond_signal(3p) - signal a condition
    pthread_cond_timedwait(3p) - wait on a condition
    pthread_cond_wait(3p) - wait on a condition
    pthread_create(3) - create a new thread
    pthread_create(3p) - thread creation
    pthread_detach(3) - detach a thread
    pthread_detach(3p) - detach a thread
    pthread_equal(3) - compare thread IDs
    pthread_equal(3p) - compare thread IDs
    pthread_exit(3) - terminate calling thread
    pthread_exit(3p) - thread termination
    pthread_getaffinity_np(3) - set/get CPU affinity of a thread
    pthread_getattr_default_np(3) - get or set default thread-creation attributes
    pthread_getattr_np(3) - get attributes of created thread
    pthread_getconcurrency(3) - set/get the concurrency level
    pthread_getconcurrency(3p) - get and set the level of concurrency
    pthread_getcpuclockid(3) - retrieve ID of a thread's CPU time clock
    pthread_getcpuclockid(3p) - time clock (ADVANCED REALTIME THREADS)
    pthread_getname_np(3) - set/get the name of a thread
    pthread_getschedparam(3) - set/get scheduling policy and parameters of a thread
    pthread_getschedparam(3p) - dynamic thread scheduling parameters access (REALTIME THREADS)
    pthread_getspecific(3p) - specific data management
    pthread_join(3) - join with a terminated thread
    pthread_join(3p) - wait for thread termination
    pthread_key_create(3p) - specific data key creation
    pthread_key_delete(3p) - specific data key deletion
    pthread_kill(3) - send a signal to a thread
    pthread_kill(3p) - send a signal to a thread
    pthread_kill_other_threads_np(3) - terminate all other threads in process
    pthread_mutexattr_destroy(3) - initialize and destroy a mutex attributes object
    pthread_mutexattr_destroy(3p) - destroy and initialize the mutex attributes object
    pthread_mutexattr_getprioceiling(3p) - get and set the prioceiling attribute of the mutex attributes object (REALTIME THREADS)
    pthread_mutexattr_getprotocol(3p) - get and set the protocol attribute of the mutex attributes object (REALTIME THREADS)
    pthread_mutexattr_getpshared(3) - get/set process-shared mutex attribute
    pthread_mutexattr_getpshared(3p) - shared attribute
    pthread_mutexattr_getrobust(3) - get and set the robustness attribute of a mutex attributes object
    pthread_mutexattr_getrobust(3p) - get and set the mutex robust attribute
    pthread_mutexattr_getrobust_np(3) - get and set the robustness attribute of a mutex attributes object
    pthread_mutexattr_gettype(3p) - get and set the mutex type attribute
    pthread_mutexattr_init(3) - initialize and destroy a mutex attributes object
    pthread_mutexattr_init(3p) - initialize the mutex attributes object
    pthread_mutexattr_setprioceiling(3p) - set the prioceiling attribute of the mutex attributes object (REALTIME THREADS)
    pthread_mutexattr_setprotocol(3p) - set the protocol attribute of the mutex attributes object (REALTIME THREADS)
    pthread_mutexattr_setpshared(3) - get/set process-shared mutex attribute
    pthread_mutexattr_setpshared(3p) - shared attribute
    pthread_mutexattr_setrobust(3) - get and set the robustness attribute of a mutex attributes object
    pthread_mutexattr_setrobust(3p) - get and set the mutex robust attribute
    pthread_mutexattr_setrobust_np(3) - get and set the robustness attribute of a mutex attributes object
    pthread_mutexattr_settype(3p) - set the mutex type attribute
    pthread_mutex_consistent(3) - make a robust mutex consistent
    pthread_mutex_consistent(3p) - mark state protected by robust mutex as consistent
    pthread_mutex_consistent_np(3) - make a robust mutex consistent
    pthread_mutex_destroy(3p) - destroy and initialize a mutex
    pthread_mutex_getprioceiling(3p) - get and set the priority ceiling of a mutex (REALTIME THREADS)
    pthread_mutex_init(3p) - destroy and initialize a mutex
    pthread_mutex_lock(3p) - lock and unlock a mutex
    pthread_mutex_setprioceiling(3p) - change the priority ceiling of a mutex (REALTIME THREADS)
    pthread_mutex_timedlock(3p) - lock a mutex
    pthread_mutex_trylock(3p) - lock and unlock a mutex
    pthread_mutex_unlock(3p) - lock and unlock a mutex
    pthread_once(3p) - dynamic package initialization
    pthread_rwlockattr_destroy(3p) - write lock attributes object
    pthread_rwlockattr_getkind_np(3) - set/get the read-write lock kind of the thread read-write lock attribute object
    pthread_rwlockattr_getpshared(3p) - shared attribute of the read-write lock attributes object
    pthread_rwlockattr_init(3p) - write lock attributes object
    pthread_rwlockattr_setkind_np(3) - set/get the read-write lock kind of the thread read-write lock attribute object
    pthread_rwlockattr_setpshared(3p) - shared attribute of the read-write lock attributes object
    pthread_rwlock_destroy(3p) - write lock object
    pthread_rwlock_init(3p) - write lock object
    pthread_rwlock_rdlock(3p) - write lock object for reading
    pthread_rwlock_timedrdlock(3p) - write lock for reading
    pthread_rwlock_timedwrlock(3p) - write lock for writing
    pthread_rwlock_tryrdlock(3p) - write lock object for reading
    pthread_rwlock_trywrlock(3p) - write lock object for writing
    pthread_rwlock_unlock(3p) - write lock object
    pthread_rwlock_wrlock(3p) - write lock object for writing
    pthreads(7) - POSIX threads
    pthread_self(3) - obtain ID of the calling thread
    pthread_self(3p) - get the calling thread ID
    pthread_setaffinity_np(3) - set/get CPU affinity of a thread
    pthread_setattr_default_np(3) - get or set default thread-creation attributes
    pthread_setcancelstate(3) - set cancelability state and type
    pthread_setcancelstate(3p) - set cancelability state
    pthread_setcanceltype(3) - set cancelability state and type
    pthread_setcanceltype(3p) - set cancelability state
    pthread_setconcurrency(3) - set/get the concurrency level
    pthread_setconcurrency(3p) - set the level of concurrency
    pthread_setname_np(3) - set/get the name of a thread
    pthread_setschedparam(3) - set/get scheduling policy and parameters of a thread
    pthread_setschedparam(3p) - dynamic thread scheduling parameters access (REALTIME THREADS)
    pthread_setschedprio(3) - set scheduling priority of a thread
    pthread_setschedprio(3p) - dynamic thread scheduling parameters access (REALTIME THREADS)
    pthread_setspecific(3p) - specific data management
    pthread_sigmask(3) - examine and change mask of blocked signals
    pthread_sigmask(3p) - examine and change blocked signals
    pthread_sigqueue(3) - queue a signal and data to a thread
    pthread_spin_destroy(3) - initialize or destroy a spin lock
    pthread_spin_destroy(3p) - destroy or initialize a spin lock object
    pthread_spin_init(3) - initialize or destroy a spin lock
    pthread_spin_init(3p) - destroy or initialize a spin lock object
    pthread_spin_lock(3) - lock and unlock a spin lock
    pthread_spin_lock(3p) - lock a spin lock object
    pthread_spin_trylock(3) - lock and unlock a spin lock
    pthread_spin_trylock(3p) - lock a spin lock object
    pthread_spin_unlock(3) - lock and unlock a spin lock
    pthread_spin_unlock(3p) - unlock a spin lock object
    pthread_testcancel(3) - request delivery of any pending cancellation request
    pthread_testcancel(3p) - set cancelability state
    pthread_timedjoin_np(3) - try to join with a terminated thread
    pthread_tryjoin_np(3) - try to join with a terminated thread
    pthread_yield(3) - yield the processor
    ptmx(4) - pseudoterminal master and slave
    ptrace(2) - process trace
    pts(4) - pseudoterminal master and slave
    ptsname(3) - get the name of the slave pseudoterminal
    ptsname(3p) - terminal device
    ptsname_r(3) - get the name of the slave pseudoterminal
    ptx(1) - produce a permuted index of file contents
    pty(7) - pseudoterminal interfaces
    putc(3) - output of characters and strings
    putc(3p) - put a byte on a stream
    putchar(3) - output of characters and strings
    putchar(3p) - put a byte on a stdout stream
    putchar_unlocked(3) - nonlocking stdio functions
    putchar_unlocked(3p) - stdio with explicit client locking
    putc_unlocked(3) - nonlocking stdio functions
    putc_unlocked(3p) - stdio with explicit client locking
    putenv(3) - change or add an environment variable
    putenv(3p) - change or add a value to an environment
    putgrent(3) - write a group database entry to a file
    putmsg(2) - unimplemented system calls
    putmsg(3p) - send a message on a STREAM (STREAMS)
    putp(3x) - curses interfaces to terminfo database
    putpmsg(2) - unimplemented system calls
    putpmsg(3p) - send a message on a STREAM (STREAMS)
    putpwent(3) - write a password file entry
    puts(3) - output of characters and strings
    puts(3p) - put a string on standard output
    putspent(3) - get shadow password file entry
    pututline(3) - access utmp file entries
    pututxline(3) - access utmp file entries
    pututxline(3p) - put an entry into the user accounting database
    putw(3) - input and output of words (ints)
    putwc(3) - write a wide character to a FILE stream
    putwc(3p) - put a wide character on a stream
    putwchar(3) - write a wide character to standard output
    putwchar(3p) - put a wide character on a stdout stream
    putwchar_unlocked(3) - nonlocking stdio functions
    putwc_unlocked(3) - nonlocking stdio functions
    putwin(3x) - miscellaneous curses utility routines
    pv(1) - monitor the progress of data through a pipe
    pvalloc(3) - allocate aligned memory
    pvchange(8) - Change attributes of physical volume(s)
    pvck(8) - Check the consistency of physical volume(s)
    pvcreate(8) - Initialize physical volume(s) for use by LVM
    pvdisplay(8) - Display various attributes of physical volume(s)
    pvmove(8) - Move extents from one physical volume to another
    pvremove(8) - Remove LVM label(s) from physical volume(s)
    pvresize(8) - Resize physical volume(s)
    pvs(8) - Display information about physical volumes
    pvscan(8) - List all physical volumes
    pwck(8) - verify integrity of password files
    pwconv(8) - convert to and from shadow passwords and groups
    pwd(1) - print name of current/working directory
    pwd(1p) - return working directory name
    pwd.h(0p) - password structure
    pwdx(1) - report current working directory of a process
    pwrite(2) - read from or write to a file descriptor at a given offset
    pwrite(3p) - write on a file
    pwrite64(2) - read from or write to a file descriptor at a given offset
    pwritev(2) - read or write data into multiple buffers
    pwritev2(2) - read or write data into multiple buffers
    pwunconv(8) - convert to and from shadow passwords and groups

top
    qalter(1p) - alter batch job
    qdel(1p) - delete batch jobs
    qecvt(3) - convert a floating-point number to a string
    qecvt_r(3) - convert a floating-point number to a string
    qfcvt(3) - convert a floating-point number to a string
    qfcvt_r(3) - convert a floating-point number to a string
    qgcvt(3) - convert a floating-point number to a string
    qhold(1p) - hold batch jobs
    qiflush(3x) - curses input options
    QMC(3) - library for managing groups of Performance Co-Pilot metrics
    qmc(3) - library for managing groups of Performance Co-Pilot metrics
    QmcContext(3) - container for a PMAPI context and its metrics
    qmccontext(3) - container for a PMAPI context and its metrics
    QmcDesc(3) - container for a metric description
    qmcdesc(3) - container for a metric description
    QmcGroup(3) - container representing a single fetch group of metrics from multiple sources
    qmcgroup(3) - container representing a single fetch group of metrics from multiple sources
    QmcIndom(3) - container for a instance domain description
    qmcindom(3) - container for a instance domain description
    QmcMetric(3) - container for a metric and all its values
    qmcmetric(3) - container for a metric and all its values
    QmcSource(3) - manages contexts created by all groups
    qmcsource(3) - manages contexts created by all groups
    qmove(1p) - move batch jobs
    qmsg(1p) - send message to batch jobs
    qrerun(1p) - rerun batch jobs
    qrls(1p) - release batch jobs
    qselect(1p) - select batch jobs
    qsig(1p) - signal batch jobs
    qsort(3) - sort an array
    qsort(3p) - sort a table of data
    qsort_r(3) - sort an array
    qstat(1p) - show status of batch jobs
    qsub(1p) - submit a script
    query_module(2) - query the kernel for various bits pertaining to modules
    query_user_context(3) - determine SELinux context(s) for user sessions
    queue(3) - linked lists, singly-linked tail queues, lists and tail queues
    quilt(1) - tool to manage series of patches
    quot(8) - summarize filesystem ownership
    quota(1) - display disk usage and limits
    quotacheck(8) - scan a filesystem for disk usage, create, check and repair quota files
    quotactl(2) - manipulate disk quotas
    quotagrpadmins(5) - users responsible for group disk usage
    quota_nld(8) - quota netlink message daemon
    quotaoff(8) - turn filesystem quotas on and off
    quotaon(8) - turn filesystem quotas on and off
    quotastats(8) - Program to query quota statistics
    quotasync(1) - synchronize in-kernel file system usage and limits to disk format
    quotatab(5) - Descriptions of devices with disk quotas

top
    raid6check(8) - check MD RAID6 device for errors aka Linux Software RAID
    raise(3) - send a signal to the caller
    raise(3p) - send a signal to the executing process
    ram(4) - ram disk device
    rand(3) - pseudo-random number generator
    rand(3p) - random number generator
    random(3) - random number generator
    random(3p) - random number
    random(4) - kernel random number source devices
    random(7) - overview of interfaces for obtaining randomness
    random_r(3) - reentrant random number generator
    rand_r(3) - pseudo-random number generator
    rand_r(3p) - random number generator
    ranlib(1) - generate index to archive.
    rarp(8) - manipulate the system RARP table
    rarpd(8) - answer RARP REQUESTs
    raw(3x) - curses input options
    raw(7) - Linux IPv4 raw sockets
    raw(8) - bind a Linux raw character device
    rawmemchr(3) - scan memory for a character
    rcmd(3) - routines for returning a stream to a remote command
    rcmd_af(3) - routines for returning a stream to a remote command
    rcopy(1) - simple file copy over RDMA.
    rdisc(8) - network router discovery daemon
    rdma-dev(8) - RDMA device configuration
    rdma-link(8) - rdma link configuration
    rdma-resource(8) - rdma resource configuration
    rdma(8) - RDMA tool
    rdma_accept(3) - Called to accept a connection request.
    rdma_ack_cm_event(3) - Free a communication event.
    rdma_bind_addr(3) - Bind an RDMA identifier to a source address.
    rdma_client(1) - simple RDMA CM connection and ping-pong test.
    rdma_cm(7) - RDMA communication manager.
    rdma_connect(3) - Initiate an active connection request.
    rdma_create_ep(3) - Allocate a communication identifier and optional QP.
    rdma_create_event_channel(3) - Open a channel used to report communication events.
    rdma_create_id(3) - Allocate a communication identifier.
    rdma_create_qp(3) - Allocate a QP.
    rdma_create_srq(3) - Allocate a shared receive queue.
    rdma_dereg_mr(3) - deregisters a registered memory region.
    rdma_destroy_ep(3) - Release a communication identifier.
    rdma_destroy_event_channel(3) - Close an event communication channel.
    rdma_destroy_id(3) - Release a communication identifier.
    rdma_destroy_qp(3) - Deallocate a QP.
    rdma_destroy_srq(3) - Deallocate a SRQ.
    rdma_disconnect(3) - This function disconnects a connection.
    rdma_event_str(3) - Returns a string representation of an rdma cm event.
    rdma_free_devices(3) - Frees the list of devices returned by rdma_get_devices.
    rdma_getaddrinfo(3) - Provides transport independent address translation.
    rdma_get_cm_event(3) - Retrieves the next pending communication event.
    rdma_get_devices(3) - Get a list of RDMA devices currently available.
    rdma_get_dst_port(3) - Returns the remote port number of a bound rdma_cm_id.
    rdma_get_local_addr(3) - Returns the local IP address of a bound rdma_cm_id.
    rdma_get_peer_addr(3) - Returns the remote IP address of a bound rdma_cm_id.
    rdma_get_recv_comp(3) - retrieves a completed receive request.
    rdma_get_request(3) - Retrieves the next pending connection request event.
    rdma_get_send_comp(3) - retrieves a completed send, read, or write request.
    rdma_get_src_port(3) - Returns the local port number of a bound rdma_cm_id.
    rdma_join_multicast(3) - Joins a multicast group.
    rdma_join_multicast_ex(3) - Joins a multicast group with extended options.
    rdmak-dev(8) - RDMA device configuration
    rdma_leave_multicast(3) - Leaves a multicast group.
    rdma_listen(3) - Listen for incoming connection requests.
    rdma_migrate_id(3) - Move a communication identifier to a different event channel.
    rdma_notify(3) - Notifies the librdmacm of an asynchronous event.
    rdma_post_read(3) - post an RDMA read work request.
    rdma_post_readv(3) - post an RDMA read work request.
    rdma_post_recv(3) - post a work request to receive an incoming message.
    rdma_post_recvv(3) - post a work request to receive incoming messages.
    rdma_post_send(3) - post a work request to send a message.
    rdma_post_sendv(3) - post a work request to send a message.
    rdma_post_ud_send(3) - post a work request to send a datagram.
    rdma_post_write(3) - post an RDMA write work request.
    rdma_post_writev(3) - post an RDMA write work request.
    rdma_reg_msgs(3) - register data buffer(s) for sending or receiving messages.
    rdma_reg_read(3) - register data buffer(s) for remote RDMA read access.
    rdma_reg_write(3) - register data buffer(s) for remote RDMA write access.
    rdma_reject(3) - Called to reject a connection request.
    rdma_resolve_addr(3) - Resolve destination and optional source addresses.
    rdma_resolve_route(3) - Resolve the route information needed to establish a connection.
    rdma_server(1) - simple RDMA CM connection and ping-pong test.
    rdma_set_option(3) - Set communication options for an rdma_cm_id.
    rdma_xclient(1) - RDMA CM communication client test program
    rdma_xserver(1) - RDMA CM communication server test program
    read(1p) - read a line from standard input
    read(2) - read from a file descriptor
    read(3p) - read from a file
    readahead(2) - initiate file readahead into page cache
    readdir(2) - read directory entry
    readdir(3) - read a directory
    readdir(3p) - read a directory
    readdir_r(3) - read a directory
    readdir_r(3p) - read a directory
    readelf(1) - Displays information about ELF files.
    readline(3) - get a line from a user with editing
    readlink(1) - print resolved symbolic links or canonical file names
    readlink(2) - read value of a symbolic link
    readlink(3p) - read the contents of a symbolic link
    readlinkat(2) - read value of a symbolic link
    readlinkat(3p) - read the contents of a symbolic link
    readlink_by_handle(3) - file handle operations
    readonly(1p) - set the readonly attribute for variables
    readprofile(8) - read kernel profiling information
    readv(2) - read or write data into multiple buffers
    readv(3p) - read a vector
    realloc(3) - allocate and free dynamic memory
    realloc(3p) - memory reallocator
    __realloc_hook(3) - malloc debugging variables
    realpath(1) - print the resolved path
    realpath(3) - return the canonicalized absolute pathname
    realpath(3p) - resolve a pathname
    reboot(2) - reboot or enable/disable Ctrl-Alt-Del
    reboot(8) - Halt, power-off or reboot the machine
    recno(3) - record number database access method
    recode-sr-latin(1) - convert Serbian text from Cyrillic to Latin script
    re_comp(3) - BSD regex functions
    recursive_key_scan(3) - apply a function to all keys in a keyring tree
    recursive_session_key_scan(3) - apply a function to all keys in a keyring tree
    recv(2) - receive a message from a socket
    recv(3p) - receive a message from a connected socket
    recvfrom(2) - receive a message from a socket
    recvfrom(3p) - receive a message from a socket
    recvmmsg(2) - receive multiple messages on a socket
    recvmsg(2) - receive a message from a socket
    recvmsg(3p) - receive a message from a socket
    red(8) - Random Early Detection
    redrawwin(3x) - refresh curses windows and lines
    re_exec(3) - BSD regex functions
    refer(1) - preprocess bibliographic references for groff
    refresh(3x) - refresh curses windows and lines
    regcomp(3) - POSIX regex functions
    regcomp(3p) - regular expression matching
    regerror(3) - POSIX regex functions
    regerror(3p) - regular expression matching
    regex(3) - POSIX regex functions
    regex(7) - POSIX.2 regular expressions
    regex.h(0p) - regular expression matching types
    regexec(3) - POSIX regex functions
    regexec(3p) - regular expression matching
    regfree(3) - POSIX regex functions
    regfree(3p) - regular expression matching
    registerrpc(3) - library routines for remote procedure calls
    remainder(3) - floating-point remainder function
    remainder(3p) - remainder function
    remainderf(3) - floating-point remainder function
    remainderf(3p) - remainder function
    remainderl(3) - floating-point remainder function
    remainderl(3p) - remainder function
    remap_file_pages(2) - create a nonlinear file mapping
    removable_context(5) - The SELinux removable devices context configuration file
    remove(3) - remove a file or directory
    remove(3p) - remove a file
    removexattr(2) - remove an extended attribute
    remque(3) - insert/remove an item from a queue
    remque(3p) - remove an element from a queue
    remquo(3) - remainder and part of quotient
    remquo(3p) - remainder functions
    remquof(3) - remainder and part of quotient
    remquof(3p) - remainder functions
    remquol(3) - remainder and part of quotient
    remquol(3p) - remainder functions
    rename(1) - rename files
    rename(2) - change the name or location of a file
    rename(3p) - rename file relative to directory file descriptor
    renameat(2) - change the name or location of a file
    renameat(3p) - rename file relative to directory file descriptor
    renameat2(2) - change the name or location of a file
    renice(1) - alter priority of running processes
    renice(1p) - set nice values of running processes
    repertoiremap(5) - map symbolic character names to Unicode code points
    replace(1) - a string-replacement utility
    repo-graph(1) - output a full package dependency graph in dot format
    repo-rss(1) - generates an RSS feed from one or more Yum repositories
    repoclosure(1) - display a list of unresolved dependencies for a yum repository
    repodiff(1) - list differences between two or more Yum repositories
    repomanage(1) - list the newest or oldest RPM packages in a directory
    repoquery(1) - query information from Yum repositories
    reposync(1) - synchronize yum repositories to a local directory
    repotrack(1) - track a package and its dependencies and download them
    repquota(8) - summarize quotas for a filesystem
    request-key(8) - handle key instantiation callback requests from the kernel
    request-key.conf(5) - Instantiation handler configuration file
    request_key(2) - request a key from the kernel's key management facility
    RESET(1) - terminal initialization
    reset(1) - initialize a terminal or query terminfo database
    reset_color_pairs(3x) - curses color manipulation routines
    reset_prog_mode(3x) - low-level curses routines
    reset_shell_mode(3x) - low-level curses routines
    resetty(3x) - low-level curses routines
    res_init(3) - resolver routines
    resize2fs(8) - ext2/ext3/ext4 file system resizer
    resizecons(8) - change kernel idea of the console size
    resizepart(8) - tell the kernel about the new size of a partition
    resizeterm(3x) - change the curses terminal size
    resize_term(3x) - change the curses terminal size
    res_mkquery(3) - resolver routines
    res_ninit(3) - resolver routines
    res_nmkquery(3) - resolver routines
    res_nquery(3) - resolver routines
    res_nquerydomain(3) - resolver routines
    res_nsearch(3) - resolver routines
    res_nsend(3) - resolver routines
    resolv.conf(5) - resolver configuration file
    resolved.conf(5) - Network Name Resolution configuration files
    resolved.conf.d(5) - Network Name Resolution configuration files
    resolveip(1) - resolve host name to IP address or vice versa
    resolver(3) - resolver routines
    resolver(5) - resolver configuration file
    resolve_stack_dump(1) - resolve numeric stack trace dump to symbols
    res_query(3) - resolver routines
    res_querydomain(3) - resolver routines
    res_search(3) - resolver routines
    res_send(3) - resolver routines
    restart_syscall(2) - restart a system call after interruption by a stop signal
    restartterm(3x) - curses interfaces to terminfo database
    restorecon(8) - restore file(s) default SELinux security contexts.
    restorecond(8) - daemon that watches for file creation and then sets the default SELinux file context
    restorecon_xattr(8) - manage security.restorecon_last extended attribute entries added by setfiles(8) or restorecon(8).
    return(1p) - return from a function or dot script
    rev(1) - reverse lines characterwise
    rewind(3) - reposition a stream
    rewind(3p) - reset the file position indicator in a stream
    rewinddir(3) - reset directory stream
    rewinddir(3p) - reset the position of a directory stream to the beginning of a directory
    rexec(3) - return stream to a remote command
    rexec_af(3) - return stream to a remote command
    rfkill(8) - tool for enabling and disabling wireless devices
    rindex(3) - locate character in string
    rint(3) - round to nearest integer
    rint(3p) - to-nearest integral value
    rintf(3) - round to nearest integer
    rintf(3p) - to-nearest integral value
    rintl(3) - round to nearest integer
    rintl(3p) - to-nearest integral value
    riostream(1) - zero-copy streaming over RDMA ping-pong test.
    ripoffline(3x) - low-level curses routines
    rm(1) - remove files or directories
    rm(1p) - remove directory entries
    rmdel(1p) - remove a delta from an SCCS file (DEVELOPMENT)
    rmdir(1) - remove empty directories
    rmdir(1p) - remove directories
    rmdir(2) - delete a directory
    rmdir(3p) - remove a directory
    rmmod(8) - Simple program to remove a module from the Linux Kernel
    roff(7) - concepts and history of roff typesetting
    roff2dvi(1) - transform roff code into dvi mode
    roff2html(1) - transform roff code into html mode
    roff2pdf(1) - transform roff code into pdf mode
    roff2ps(1) - transform roff code into ps mode
    roff2text(1) - transform roff code into text mode
    roff2x(1) - transform roff code into x mode
    round(3) - round to nearest integer, away from zero
    round(3p) - point format
    roundf(3) - round to nearest integer, away from zero
    roundf(3p) - point format
    roundl(3) - round to nearest integer, away from zero
    roundl(3p) - point format
    route(8) - show / manipulate the IP routing table
    routef(8) - list routes with pretty output format
    routel(8) - list routes with pretty output format
    rpc(3) - library routines for remote procedure calls
    rpc(5) - RPC program number data base
    rpc.gssd(8) - RPCSEC_GSS daemon
    rpc.idmapd(8) - > Name Mapper
    rpc.mountd(8) - NFS mount daemon
    rpc.nfsd(8) - NFS server process
    rpc.rquotad(8) - remote quota server
    rpc.statd(8) - NSM service daemon
    rpc.svcgssd(8) - server-side rpcsec_gss daemon
    rpcbind(8) - universal addresses to RPC program number mapper
    rpcdebug(8) - set and clear NFS and RPC kernel debug flags
    rpcinfo(8) - report RPC information
    rping(1) - RDMA CM connection and RDMA ping-pong test.
    rpmatch(3) - determine if the answer to a question is affirmative or negative
    rpm_execcon(3) - get or set the SELinux security context used for executing a new process
    rquota(3) - implement quotas on remote machines
    rresvport(3) - routines for returning a stream to a remote command
    rresvport_af(3) - routines for returning a stream to a remote command
    rstream(1) - streaming over RDMA ping-pong test.
    rsync(1) - a fast, versatile, remote (and local) file-copying tool
    rsyncd.conf(5) - configuration file for rsync in daemon mode
    rsyslog.conf(5) - rsyslogd(8) configuration file
    rsyslogd(8) - reliable and extended syslogd
    rtacct(8) - network statistics tools.
    rtc(4) - real-time clock
    rtcwake(8) - enter a system sleep state until specified wakeup time
    rtime(3) - get time from a remote machine
    rtld-audit(7) - auditing API for the dynamic linker
    rtmon(8) - listens to and monitors RTnetlink
    rtnetlink(3) - macros to manipulate rtnetlink messages
    rtnetlink(7) - Linux IPv4 routing socket
    rtpr(8) - replace backslashes with newlines.
    rt_sigaction(2) - examine and change a signal action
    rt_sigpending(2) - examine pending signals
    rt_sigprocmask(2) - examine and change blocked signals
    rt_sigqueueinfo(2) - queue a signal and data
    rt_sigreturn(2) - return from signal handler and cleanup stack frame
    rt_sigsuspend(2) - wait for a signal
    rt_sigtimedwait(2) - synchronously wait for queued signals
    rtstat(8) - unified linux network statistics
    rt_tgsigqueueinfo(2) - queue a signal and data
    runcon(1) - run command with specified security context
    run_init(8) - run an init script in the proper SELinux context
    runlevel(8) - Print previous and current SysV runlevel
    runuser(1) - run a command with substitute user and group ID
    ruserok(3) - routines for returning a stream to a remote command
    ruserok_af(3) - routines for returning a stream to a remote command
    rxe(7) - Software RDMA over Ethernet
    rxe_cfg(8) - rxe configuration tool for RXE (Soft RoCE)

top
    s390_pci_mmio_read(2) - transfer data to/from PCI MMIO memory page
    s390_pci_mmio_write(2) - transfer data to/from PCI MMIO memory page
    s390_runtime_instr(2) - enable/disable s390 CPU run-time instrumentation
    s390_sthyi(2) - emulate STHYI instruction
    sa(8) - summarizes accounting information
    sa1(8) - Collect and store binary data in the system activity daily data file.
    sa2(8) - Create a report from the current standard system activity daily data file.
    sact(1p) - editing activity (DEVELOPMENT)
    sadc(8) - System activity data collector.
    sadf(1) - Display data collected by sar in multiple formats.
    sample(8) - packet sampling tc action
    sandbox(5) - user config file for the SELinux sandbox
    sandbox(8) - Run cmd under an SELinux sandbox
    sandbox.conf(5) - user config file for the SELinux sandbox
    sar(1) - Collect, report, or save system activity information.
    sar2pcp(1) - import sar data and create a PCP archive
    savetty(3x) - low-level curses routines
    sbrk(2) - change data segment size
    scalb(3) - multiply floating-point number by integral power of radix (OBSOLETE)
    scalbf(3) - multiply floating-point number by integral power of radix (OBSOLETE)
    scalbl(3) - multiply floating-point number by integral power of radix (OBSOLETE)
    scalbln(3) - multiply floating-point number by integral power of radix
    scalbln(3p) - compute exponent using FLT_RADIX
    scalblnf(3) - multiply floating-point number by integral power of radix
    scalblnf(3p) - compute exponent using FLT_RADIX
    scalblnl(3) - multiply floating-point number by integral power of radix
    scalblnl(3p) - compute exponent using FLT_RADIX
    scalbn(3) - multiply floating-point number by integral power of radix
    scalbn(3p) - compute exponent using FLT_RADIX
    scalbnf(3) - multiply floating-point number by integral power of radix
    scalbnf(3p) - compute exponent using FLT_RADIX
    scalbnl(3) - multiply floating-point number by integral power of radix
    scalbnl(3p) - compute exponent using FLT_RADIX
    scandir(3) - scan a directory for matching entries
    scandir(3p) - scan a directory
    scandirat(3) - scan a directory for matching entries
    scanf(3) - input format conversion
    scanf(3p) - convert formatted input
    scanw(3x) - convert formatted input from a curses window
    sccs(1p) - front end for the SCCS subsystem (DEVELOPMENT)
    sched(7) - overview of CPU scheduling
    sched.h(0p) - execution scheduling
    sched_getaffinity(2) - set and get a thread's CPU affinity mask
    sched_getattr(2) - set and get scheduling policy and attributes
    sched_getcpu(3) - determine CPU on which the calling thread is running
    sched_getparam(2) - set and get scheduling parameters
    sched_getparam(3p) - get scheduling parameters (REALTIME)
    sched_get_priority_max(2) - get static priority range
    sched_get_priority_max(3p) - get priority limits (REALTIME)
    sched_get_priority_min(2) - get static priority range
    sched_get_priority_min(3p) - get priority limits (REALTIME)
    sched_getscheduler(2) - set and get scheduling policy/parameters
    sched_getscheduler(3p) - get scheduling policy (REALTIME)
    sched_rr_get_interval(2) - get the SCHED_RR interval for the named process
    sched_rr_get_interval(3p) - get execution time limits (REALTIME)
    sched_setaffinity(2) - set and get a thread's CPU affinity mask
    sched_setattr(2) - set and get scheduling policy and attributes
    sched_setparam(2) - set and get scheduling parameters
    sched_setparam(3p) - set scheduling parameters (REALTIME)
    sched_setscheduler(2) - set and get scheduling policy/parameters
    sched_setscheduler(3p) - set scheduling policy and parameters (REALTIME)
    sched_yield(2) - yield the processor
    sched_yield(3p) - yield the processor
    scmp_sys_resolver(1) - Resolve system calls
    scp(1) - secure copy (remote file copy program)
    scr_dump(3x) - read (write) a curses screen from (to) a file
    scr_dump(5) - format of curses screen-dumps.
    screen(1) - screen manager with VT100/ANSI terminal emulation
    scr_init(3x) - read (write) a curses screen from (to) a file
    script(1) - make typescript of terminal session
    scriptreplay(1) - play back typescripts, using timing information
    scrl(3x) - scroll a curses window
    scroll(3x) - scroll a curses window
    scrollok(3x) - curses output options
    scr_restore(3x) - read (write) a curses screen from (to) a file
    scr_set(3x) - read (write) a curses screen from (to) a file
    sctp(7) - SCTP protocol.
    sctp_bindx(3) - Add or remove bind addresses on a socket.
    sctp_connectx(3) - initiate a connection on an SCTP socket using multiple destination addresses.
    sctp_getladdrs(3) - Returns all locally bound addresses on a socket.
    sctp_getpaddrs(3) - Returns all peer addresses in an association.
    sctp_optinfo(3) - Get options on a SCTP socket.
    sctp_opt_info(3) - Get options on a SCTP socket.
    sctp_peeloff(3) - Branch off an association into a separate socket.
    sctp_recvmsg(3) - Receive a message from a SCTP socket.
    sctp_recvv(3) - Receive a message from a SCTP socket with an extensible way.
    sctp_send(3) - Send a message from a SCTP socket.
    sctp_sendmsg(3) - Send a message from a SCTP socket.
    sctp_sendv(3) - Send messages from a SCTP socket with an extensible way.
    sd-bus-errors(3) - Standard D-Bus error names
    sd-bus(3) - A lightweight D-Bus IPC client library
    sd-daemon(3) - APIs for new-style daemons
    sd-event(3) - A generic event loop implementation
    sd-id128(3) - APIs for processing 128-bit IDs
    sd-journal(3) - APIs for submitting and querying log entries to and from the journal
    sd-login(3) - APIs for tracking logins
    sd(4) - driver for SCSI disk drives
    SD_ALERT(3) - APIs for new-style daemons
    sd_alert(3) - APIs for new-style daemons
    sd_booted(3) - Test whether the system is running the systemd init system
    sd_bus_add_match(3) - Add a match rule for message dispatching
    sd_bus_creds_get_audit_login_uid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_audit_session_id(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_augmented_mask(3) - Retrieve credentials object for the specified PID
    sd_bus_creds_get_cgroup(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_cmdline(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_comm(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_description(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_egid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_euid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_exe(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_fsgid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_fsuid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_gid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_mask(3) - Retrieve credentials object for the specified PID
    sd_bus_creds_get_owner_uid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_pid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_ppid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_selinux_context(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_session(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_sgid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_slice(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_suid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_supplementary_gids(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_tid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_tid_comm(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_tty(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_uid(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_unique_name(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_unit(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_user_slice(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_user_unit(3) - Retrieve fields from a credentials object
    sd_bus_creds_get_well_known_names(3) - Retrieve fields from a credentials object
    sd_bus_creds_has_bounding_cap(3) - Retrieve fields from a credentials object
    sd_bus_creds_has_effective_cap(3) - Retrieve fields from a credentials object
    sd_bus_creds_has_inheritable_cap(3) - Retrieve fields from a credentials object
    sd_bus_creds_has_permitted_cap(3) - Retrieve fields from a credentials object
    sd_bus_creds_new_from_pid(3) - Retrieve credentials object for the specified PID
    sd_bus_creds_ref(3) - Retrieve credentials object for the specified PID
    sd_bus_creds_unref(3) - Retrieve credentials object for the specified PID
    sd_bus_creds_unrefp(3) - Retrieve credentials object for the specified PID
    sd_bus_default(3) - Acquire a connection to a system or user bus
    sd_bus_default_system(3) - Acquire a connection to a system or user bus
    sd_bus_default_user(3) - Acquire a connection to a system or user bus
    sd_bus_error(3) - sd-bus error handling
    SD_BUS_ERROR_ACCESS_DENIED(3) - Standard D-Bus error names
    sd_bus_error_access_denied(3) - Standard D-Bus error names
    sd_bus_error_add_map(3) - Additional sd-dbus error mappings
    SD_BUS_ERROR_ADDRESS_IN_USE(3) - Standard D-Bus error names
    sd_bus_error_address_in_use(3) - Standard D-Bus error names
    SD_BUS_ERROR_AUTH_FAILED(3) - Standard D-Bus error names
    sd_bus_error_auth_failed(3) - Standard D-Bus error names
    SD_BUS_ERROR_BAD_ADDRESS(3) - Standard D-Bus error names
    sd_bus_error_bad_address(3) - Standard D-Bus error names
    sd_bus_error_copy(3) - sd-bus error handling
    SD_BUS_ERROR_DISCONNECTED(3) - Standard D-Bus error names
    sd_bus_error_disconnected(3) - Standard D-Bus error names
    SD_BUS_ERROR_END(3) - Additional sd-dbus error mappings
    sd_bus_error_end(3) - Additional sd-dbus error mappings
    SD_BUS_ERROR_FAILED(3) - Standard D-Bus error names
    sd_bus_error_failed(3) - Standard D-Bus error names
    SD_BUS_ERROR_FILE_EXISTS(3) - Standard D-Bus error names
    sd_bus_error_file_exists(3) - Standard D-Bus error names
    SD_BUS_ERROR_FILE_NOT_FOUND(3) - Standard D-Bus error names
    sd_bus_error_file_not_found(3) - Standard D-Bus error names
    sd_bus_error_free(3) - sd-bus error handling
    sd_bus_error_get_errno(3) - sd-bus error handling
    sd_bus_error_has_name(3) - sd-bus error handling
    SD_BUS_ERROR_INCONSISTENT_MESSAGE(3) - Standard D-Bus error names
    sd_bus_error_inconsistent_message(3) - Standard D-Bus error names
    SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED(3) - Standard D-Bus error names
    sd_bus_error_interactive_authorization_required(3) - Standard D-Bus error names
    SD_BUS_ERROR_INVALID_ARGS(3) - Standard D-Bus error names
    sd_bus_error_invalid_args(3) - Standard D-Bus error names
    SD_BUS_ERROR_INVALID_SIGNATURE(3) - Standard D-Bus error names
    sd_bus_error_invalid_signature(3) - Standard D-Bus error names
    SD_BUS_ERROR_IO_ERROR(3) - Standard D-Bus error names
    sd_bus_error_io_error(3) - Standard D-Bus error names
    sd_bus_error_is_set(3) - sd-bus error handling
    SD_BUS_ERROR_LIMITS_EXCEEDED(3) - Standard D-Bus error names
    sd_bus_error_limits_exceeded(3) - Standard D-Bus error names
    SD_BUS_ERROR_MAKE_CONST(3) - sd-bus error handling
    sd_bus_error_make_const(3) - sd-bus error handling
    SD_BUS_ERROR_MAP(3) - Additional sd-dbus error mappings
    sd_bus_error_map(3) - Additional sd-dbus error mappings
    SD_BUS_ERROR_MATCH_RULE_INVALID(3) - Standard D-Bus error names
    sd_bus_error_match_rule_invalid(3) - Standard D-Bus error names
    SD_BUS_ERROR_MATCH_RULE_NOT_FOUND(3) - Standard D-Bus error names
    sd_bus_error_match_rule_not_found(3) - Standard D-Bus error names
    SD_BUS_ERROR_NAME_HAS_NO_OWNER(3) - Standard D-Bus error names
    sd_bus_error_name_has_no_owner(3) - Standard D-Bus error names
    SD_BUS_ERROR_NO_MEMORY(3) - Standard D-Bus error names
    sd_bus_error_no_memory(3) - Standard D-Bus error names
    SD_BUS_ERROR_NO_NETWORK(3) - Standard D-Bus error names
    sd_bus_error_no_network(3) - Standard D-Bus error names
    SD_BUS_ERROR_NO_REPLY(3) - Standard D-Bus error names
    sd_bus_error_no_reply(3) - Standard D-Bus error names
    SD_BUS_ERROR_NO_SERVER(3) - Standard D-Bus error names
    sd_bus_error_no_server(3) - Standard D-Bus error names
    SD_BUS_ERROR_NOT_SUPPORTED(3) - Standard D-Bus error names
    sd_bus_error_not_supported(3) - Standard D-Bus error names
    SD_BUS_ERROR_NULL(3) - sd-bus error handling
    sd_bus_error_null(3) - sd-bus error handling
    SD_BUS_ERROR_PROPERTY_READ_ONLY(3) - Standard D-Bus error names
    sd_bus_error_property_read_only(3) - Standard D-Bus error names
    SD_BUS_ERROR_SERVICE_UNKNOWN(3) - Standard D-Bus error names
    sd_bus_error_service_unknown(3) - Standard D-Bus error names
    sd_bus_error_set(3) - sd-bus error handling
    sd_bus_error_set_const(3) - sd-bus error handling
    sd_bus_error_set_errno(3) - sd-bus error handling
    sd_bus_error_set_errnof(3) - sd-bus error handling
    sd_bus_error_set_errnofv(3) - sd-bus error handling
    sd_bus_error_setf(3) - sd-bus error handling
    SD_BUS_ERROR_TIMEOUT(3) - Standard D-Bus error names
    sd_bus_error_timeout(3) - Standard D-Bus error names
    SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN(3) - Standard D-Bus error names
    sd_bus_error_unix_process_id_unknown(3) - Standard D-Bus error names
    SD_BUS_ERROR_UNKNOWN_INTERFACE(3) - Standard D-Bus error names
    sd_bus_error_unknown_interface(3) - Standard D-Bus error names
    SD_BUS_ERROR_UNKNOWN_METHOD(3) - Standard D-Bus error names
    sd_bus_error_unknown_method(3) - Standard D-Bus error names
    SD_BUS_ERROR_UNKNOWN_OBJECT(3) - Standard D-Bus error names
    sd_bus_error_unknown_object(3) - Standard D-Bus error names
    SD_BUS_ERROR_UNKNOWN_PROPERTY(3) - Standard D-Bus error names
    sd_bus_error_unknown_property(3) - Standard D-Bus error names
    sd_bus_get_fd(3) - Get the file descriptor connected to the message bus
    sd_bus_message_append(3) - Attach fields to a D-Bus message based on a type string
    sd_bus_message_append_array(3) - Append an array of fields to a D-Bus message
    sd_bus_message_append_array_iovec(3) - Append an array of fields to a D-Bus message
    sd_bus_message_append_array_memfd(3) - Append an array of fields to a D-Bus message
    sd_bus_message_append_array_space(3) - Append an array of fields to a D-Bus message
    sd_bus_message_append_basic(3) - Attach a single field to a message
    sd_bus_message_append_string_iovec(3) - Attach a string to a message
    sd_bus_message_append_string_memfd(3) - Attach a string to a message
    sd_bus_message_append_string_space(3) - Attach a string to a message
    sd_bus_message_append_strv(3) - Attach an array of strings to a message
    sd_bus_message_appendv(3) - Attach fields to a D-Bus message based on a type string
    sd_bus_message_get_cookie(3) - Returns the transaction cookie of a message
    sd_bus_message_get_monotonic_usec(3) - Retrieve the sender timestamps and sequence number of a message
    sd_bus_message_get_realtime_usec(3) - Retrieve the sender timestamps and sequence number of a message
    sd_bus_message_get_reply_cookie(3) - Returns the transaction cookie of a message
    sd_bus_message_get_seqnum(3) - Retrieve the sender timestamps and sequence number of a message
    sd_bus_message_read_basic(3) - Read a basic type from a message
    sd_bus_negotiate_creds(3) - Control feature negotiation on bus connections
    sd_bus_negotiate_fds(3) - Control feature negotiation on bus connections
    sd_bus_negotiate_timestamp(3) - Control feature negotiation on bus connections
    sd_bus_new(3) - Create a new bus object and create or destroy references to it
    sd_bus_open(3) - Acquire a connection to a system or user bus
    sd_bus_open_system(3) - Acquire a connection to a system or user bus
    sd_bus_open_system_machine(3) - Acquire a connection to a system or user bus
    sd_bus_open_system_remote(3) - Acquire a connection to a system or user bus
    sd_bus_open_user(3) - Acquire a connection to a system or user bus
    sd_bus_path_decode(3) - Convert an external identifier into an object path and back
    sd_bus_path_decode_many(3) - Convert an external identifier into an object path and back
    sd_bus_path_encode(3) - Convert an external identifier into an object path and back
    sd_bus_path_encode_many(3) - Convert an external identifier into an object path and back
    sd_bus_process(3) - Drive the connection
    sd_bus_ref(3) - Create a new bus object and create or destroy references to it
    sd_bus_release_name(3) - Request or release a well-known service name on a bus
    sd_bus_request_name(3) - Request or release a well-known service name on a bus
    sd_bus_track_add_name(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_add_sender(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_contains(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_count(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_count_name(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_count_sender(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_first(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_get_bus(3) - Track bus peers
    sd_bus_track_get_recursive(3) - Track bus peers
    sd_bus_track_get_userdata(3) - Track bus peers
    sd_bus_track_new(3) - Track bus peers
    sd_bus_track_next(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_ref(3) - Track bus peers
    sd_bus_track_remove_name(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_remove_sender(3) - Add, remove and retrieve bus peers tracked in a bus peer tracking object
    sd_bus_track_set_recursive(3) - Track bus peers
    sd_bus_track_set_userdata(3) - Track bus peers
    sd_bus_track_unref(3) - Track bus peers
    sd_bus_track_unrefp(3) - Track bus peers
    sd_bus_unref(3) - Create a new bus object and create or destroy references to it
    sd_bus_unrefp(3) - Create a new bus object and create or destroy references to it
    SD_CRIT(3) - APIs for new-style daemons
    sd_crit(3) - APIs for new-style daemons
    SD_DEBUG(3) - APIs for new-style daemons
    sd_debug(3) - APIs for new-style daemons
    SD_EMERG(3) - APIs for new-style daemons
    sd_emerg(3) - APIs for new-style daemons
    SD_ERR(3) - APIs for new-style daemons
    sd_err(3) - APIs for new-style daemons
    sd_event(3) - Acquire and release an event loop object
    sd_event_add_child(3) - Add a child process state change event source to an event loop
    sd_event_add_defer(3) - Add static event sources to an event loop
    sd_event_add_exit(3) - Add static event sources to an event loop
    sd_event_add_io(3) - Add an I/O event source to an event loop
    sd_event_add_post(3) - Add static event sources to an event loop
    sd_event_add_signal(3) - Add a UNIX process signal event source to an event loop
    sd_event_add_time(3) - Add a timer event source to an event loop
    SD_EVENT_ARMED(3) - Low-level event loop operations
    sd_event_armed(3) - Low-level event loop operations
    sd_event_child_handler_t(3) - Add a child process state change event source to an event loop
    sd_event_default(3) - Acquire and release an event loop object
    sd_event_dispatch(3) - Low-level event loop operations
    sd_event_exit(3) - Ask the event loop to exit
    SD_EVENT_EXITING(3) - Low-level event loop operations
    sd_event_exiting(3) - Low-level event loop operations
    SD_EVENT_FINISHED(3) - Low-level event loop operations
    sd_event_finished(3) - Low-level event loop operations
    sd_event_get_exit_code(3) - Ask the event loop to exit
    sd_event_get_fd(3) - Obtain a file descriptor to poll for event loop events
    sd_event_get_iteration(3) - Low-level event loop operations
    sd_event_get_state(3) - Low-level event loop operations
    sd_event_get_tid(3) - Acquire and release an event loop object
    sd_event_get_watchdog(3) - Enable event loop watchdog support
    sd_event_handler_t(3) - Add static event sources to an event loop
    SD_EVENT_INITIAL(3) - Low-level event loop operations
    sd_event_initial(3) - Low-level event loop operations
    sd_event_io_handler_t(3) - Add an I/O event source to an event loop
    sd_event_loop(3) - Run an event loop
    sd_event_new(3) - Acquire and release an event loop object
    sd_event_now(3) - Retrieve current event loop iteration timestamp
    SD_EVENT_OFF(3) - Enable or disable event sources
    sd_event_off(3) - Enable or disable event sources
    SD_EVENT_ON(3) - Enable or disable event sources
    sd_event_on(3) - Enable or disable event sources
    SD_EVENT_ONESHOT(3) - Enable or disable event sources
    sd_event_oneshot(3) - Enable or disable event sources
    SD_EVENT_PENDING(3) - Low-level event loop operations
    sd_event_pending(3) - Low-level event loop operations
    sd_event_prepare(3) - Low-level event loop operations
    SD_EVENT_PREPARING(3) - Low-level event loop operations
    sd_event_preparing(3) - Low-level event loop operations
    SD_EVENT_PRIORITY_IDLE(3) - Set or retrieve the priority of event sources
    sd_event_priority_idle(3) - Set or retrieve the priority of event sources
    SD_EVENT_PRIORITY_IMPORTANT(3) - Set or retrieve the priority of event sources
    sd_event_priority_important(3) - Set or retrieve the priority of event sources
    SD_EVENT_PRIORITY_NORMAL(3) - Set or retrieve the priority of event sources
    sd_event_priority_normal(3) - Set or retrieve the priority of event sources
    sd_event_ref(3) - Acquire and release an event loop object
    sd_event_run(3) - Run an event loop
    SD_EVENT_RUNNING(3) - Low-level event loop operations
    sd_event_running(3) - Low-level event loop operations
    sd_event_set_watchdog(3) - Enable event loop watchdog support
    sd_event_signal_handler_t(3) - Add a UNIX process signal event source to an event loop
    sd_event_source(3) - Add an I/O event source to an event loop
    sd_event_source_get_child_pid(3) - Add a child process state change event source to an event loop
    sd_event_source_get_description(3) - Set or retrieve descriptive names of event sources
    sd_event_source_get_enabled(3) - Enable or disable event sources
    sd_event_source_get_event(3) - Retrieve the event loop of an event source
    sd_event_source_get_io_events(3) - Add an I/O event source to an event loop
    sd_event_source_get_io_fd(3) - Add an I/O event source to an event loop
    sd_event_source_get_io_revents(3) - Add an I/O event source to an event loop
    sd_event_source_get_pending(3) - Determine pending state of event sources
    sd_event_source_get_priority(3) - Set or retrieve the priority of event sources
    sd_event_source_get_signal(3) - Add a UNIX process signal event source to an event loop
    sd_event_source_get_time(3) - Add a timer event source to an event loop
    sd_event_source_get_time_accuracy(3) - Add a timer event source to an event loop
    sd_event_source_get_time_clock(3) - Add a timer event source to an event loop
    sd_event_source_get_userdata(3) - Set or retrieve user data pointer of event sources
    sd_event_source_ref(3) - Increase or decrease event source reference counters
    sd_event_source_set_description(3) - Set or retrieve descriptive names of event sources
    sd_event_source_set_enabled(3) - Enable or disable event sources
    sd_event_source_set_io_events(3) - Add an I/O event source to an event loop
    sd_event_source_set_io_fd(3) - Add an I/O event source to an event loop
    sd_event_source_set_prepare(3) - Set a preparation callback for event sources
    sd_event_source_set_priority(3) - Set or retrieve the priority of event sources
    sd_event_source_set_time(3) - Add a timer event source to an event loop
    sd_event_source_set_time_accuracy(3) - Add a timer event source to an event loop
    sd_event_source_set_userdata(3) - Set or retrieve user data pointer of event sources
    sd_event_source_unref(3) - Increase or decrease event source reference counters
    sd_event_source_unrefp(3) - Increase or decrease event source reference counters
    sd_event_time_handler_t(3) - Add a timer event source to an event loop
    sd_event_unref(3) - Acquire and release an event loop object
    sd_event_unrefp(3) - Acquire and release an event loop object
    sd_event_wait(3) - Low-level event loop operations
    sd_get_machine_names(3) - Determine available seats, sessions, logged in users and virtual machines/containers
    sd_get_seats(3) - Determine available seats, sessions, logged in users and virtual machines/containers
    sd_get_sessions(3) - Determine available seats, sessions, logged in users and virtual machines/containers
    sd_get_uids(3) - Determine available seats, sessions, logged in users and virtual machines/containers
    SD_ID128_CONST_STR(3) - APIs for processing 128-bit IDs
    sd_id128_const_str(3) - APIs for processing 128-bit IDs
    sd_id128_equal(3) - APIs for processing 128-bit IDs
    SD_ID128_FORMAT_STR(3) - APIs for processing 128-bit IDs
    sd_id128_format_str(3) - APIs for processing 128-bit IDs
    SD_ID128_FORMAT_VAL(3) - APIs for processing 128-bit IDs
    sd_id128_format_val(3) - APIs for processing 128-bit IDs
    sd_id128_from_string(3) - Format or parse 128-bit IDs as strings
    sd_id128_get_boot(3) - Retrieve 128-bit IDs
    sd_id128_get_invocation(3) - Retrieve 128-bit IDs
    sd_id128_get_machine(3) - Retrieve 128-bit IDs
    sd_id128_get_machine_app_specific(3) - Retrieve 128-bit IDs
    sd_id128_is_null(3) - APIs for processing 128-bit IDs
    SD_ID128_MAKE(3) - APIs for processing 128-bit IDs
    sd_id128_make(3) - APIs for processing 128-bit IDs
    SD_ID128_MAKE_STR(3) - APIs for processing 128-bit IDs
    sd_id128_make_str(3) - APIs for processing 128-bit IDs
    SD_ID128_NULL(3) - APIs for processing 128-bit IDs
    sd_id128_null(3) - APIs for processing 128-bit IDs
    sd_id128_randomize(3) - Generate 128-bit IDs
    sd_id128_t(3) - APIs for processing 128-bit IDs
    sd_id128_to_string(3) - Format or parse 128-bit IDs as strings
    sdiff(1) - side-by-side merge of file differences
    SD_INFO(3) - APIs for new-style daemons
    sd_info(3) - APIs for new-style daemons
    sd_is_fifo(3) - Check the type of a file descriptor
    sd_is_mq(3) - Check the type of a file descriptor
    sd_is_socket(3) - Check the type of a file descriptor
    sd_is_socket_inet(3) - Check the type of a file descriptor
    sd_is_socket_sockaddr(3) - Check the type of a file descriptor
    sd_is_socket_unix(3) - Check the type of a file descriptor
    sd_is_special(3) - Check the type of a file descriptor
    sd_journal(3) - Open the system journal for reading
    sd_journal_add_conjunction(3) - Add or remove entry matches
    sd_journal_add_disjunction(3) - Add or remove entry matches
    sd_journal_add_match(3) - Add or remove entry matches
    SD_JOURNAL_APPEND(3) - Journal change notification interface
    sd_journal_append(3) - Journal change notification interface
    sd_journal_close(3) - Open the system journal for reading
    SD_JOURNAL_CURRENT_USER(3) - Open the system journal for reading
    sd_journal_current_user(3) - Open the system journal for reading
    sd_journal_enumerate_data(3) - Read data fields from the current journal entry
    sd_journal_enumerate_fields(3) - Read used field names from the journal
    sd_journal_enumerate_unique(3) - Read unique data fields from the journal
    sd_journal_flush_matches(3) - Add or remove entry matches
    SD_JOURNAL_FOREACH(3) - Advance or set back the read pointer in the journal
    sd_journal_foreach(3) - Advance or set back the read pointer in the journal
    SD_JOURNAL_FOREACH_BACKWARDS(3) - Advance or set back the read pointer in the journal
    sd_journal_foreach_backwards(3) - Advance or set back the read pointer in the journal
    SD_JOURNAL_FOREACH_DATA(3) - Read data fields from the current journal entry
    sd_journal_foreach_data(3) - Read data fields from the current journal entry
    SD_JOURNAL_FOREACH_FIELD(3) - Read used field names from the journal
    sd_journal_foreach_field(3) - Read used field names from the journal
    SD_JOURNAL_FOREACH_UNIQUE(3) - Read unique data fields from the journal
    sd_journal_foreach_unique(3) - Read unique data fields from the journal
    sd_journal_get_catalog(3) - Retrieve message catalog entry
    sd_journal_get_catalog_for_message_id(3) - Retrieve message catalog entry
    sd_journal_get_cursor(3) - Get cursor string for or test cursor string against the current journal entry
    sd_journal_get_cutoff_monotonic_usec(3) - Read cut-off timestamps from the current journal entry
    sd_journal_get_cutoff_realtime_usec(3) - Read cut-off timestamps from the current journal entry
    sd_journal_get_data(3) - Read data fields from the current journal entry
    sd_journal_get_data_threshold(3) - Read data fields from the current journal entry
    sd_journal_get_events(3) - Journal change notification interface
    sd_journal_get_fd(3) - Journal change notification interface
    sd_journal_get_monotonic_usec(3) - Read timestamps from the current journal entry
    sd_journal_get_realtime_usec(3) - Read timestamps from the current journal entry
    sd_journal_get_timeout(3) - Journal change notification interface
    sd_journal_get_usage(3) - Journal disk usage
    sd_journal_has_persistent_files(3) - Query availability of runtime or persistent journal files.
    sd_journal_has_runtime_files(3) - Query availability of runtime or persistent journal files.
    SD_JOURNAL_INVALIDATE(3) - Journal change notification interface
    sd_journal_invalidate(3) - Journal change notification interface
    SD_JOURNAL_LOCAL_ONLY(3) - Open the system journal for reading
    sd_journal_local_only(3) - Open the system journal for reading
    sd_journal_next(3) - Advance or set back the read pointer in the journal
    sd_journal_next_skip(3) - Advance or set back the read pointer in the journal
    SD_JOURNAL_NOP(3) - Journal change notification interface
    sd_journal_nop(3) - Journal change notification interface
    sd_journal_open(3) - Open the system journal for reading
    sd_journal_open_container(3) - Open the system journal for reading
    sd_journal_open_directory(3) - Open the system journal for reading
    sd_journal_open_directory_fd(3) - Open the system journal for reading
    sd_journal_open_files(3) - Open the system journal for reading
    sd_journal_open_files_fd(3) - Open the system journal for reading
    SD_JOURNAL_OS_ROOT(3) - Open the system journal for reading
    sd_journal_os_root(3) - Open the system journal for reading
    sd_journal_perror(3) - Submit log entries to the journal
    sd_journal_previous(3) - Advance or set back the read pointer in the journal
    sd_journal_previous_skip(3) - Advance or set back the read pointer in the journal
    sd_journal_print(3) - Submit log entries to the journal
    sd_journal_printv(3) - Submit log entries to the journal
    sd_journal_process(3) - Journal change notification interface
    sd_journal_query_unique(3) - Read unique data fields from the journal
    sd_journal_reliable_fd(3) - Journal change notification interface
    sd_journal_restart_data(3) - Read data fields from the current journal entry
    sd_journal_restart_fields(3) - Read used field names from the journal
    sd_journal_restart_unique(3) - Read unique data fields from the journal
    SD_JOURNAL_RUNTIME_ONLY(3) - Open the system journal for reading
    sd_journal_runtime_only(3) - Open the system journal for reading
    sd_journal_seek_cursor(3) - Seek to a position in the journal
    sd_journal_seek_head(3) - Seek to a position in the journal
    sd_journal_seek_monotonic_usec(3) - Seek to a position in the journal
    sd_journal_seek_realtime_usec(3) - Seek to a position in the journal
    sd_journal_seek_tail(3) - Seek to a position in the journal
    sd_journal_send(3) - Submit log entries to the journal
    sd_journal_sendv(3) - Submit log entries to the journal
    sd_journal_set_data_threshold(3) - Read data fields from the current journal entry
    sd_journal_stream_fd(3) - Create log stream file descriptor to the journal
    SD_JOURNAL_SUPPRESS_LOCATION(3) - Submit log entries to the journal
    sd_journal_suppress_location(3) - Submit log entries to the journal
    SD_JOURNAL_SYSTEM(3) - Open the system journal for reading
    sd_journal_system(3) - Open the system journal for reading
    sd_journal_test_cursor(3) - Get cursor string for or test cursor string against the current journal entry
    sd_journal_wait(3) - Journal change notification interface
    sd_listen_fds(3) - Check for file descriptors passed by the system manager
    SD_LISTEN_FDS_START(3) - Check for file descriptors passed by the system manager
    sd_listen_fds_start(3) - Check for file descriptors passed by the system manager
    sd_listen_fds_with_names(3) - Check for file descriptors passed by the system manager
    sd_login_monitor(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_login_monitor_flush(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_login_monitor_get_events(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_login_monitor_get_fd(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_login_monitor_get_timeout(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_login_monitor_new(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_login_monitor_unref(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_login_monitor_unrefp(3) - Monitor login sessions, seats, users and virtual machines/containers
    sd_machine_get_class(3) - Determine the class and network interface indices of a locally running virtual machine or container.
    sd_machine_get_ifindices(3) - Determine the class and network interface indices of a locally running virtual machine or container.
    SD_NOTICE(3) - APIs for new-style daemons
    sd_notice(3) - APIs for new-style daemons
    sd_notify(3) - Notify service manager about start-up completion and other service status changes
    sd_notifyf(3) - Notify service manager about start-up completion and other service status changes
    sd_peer_get_cgroup(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_peer_get_machine_name(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_peer_get_owner_uid(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_peer_get_session(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_peer_get_slice(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_peer_get_unit(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_peer_get_user_slice(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_peer_get_user_unit(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_cgroup(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_machine_name(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_owner_uid(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_session(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_slice(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_unit(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_user_slice(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_get_user_unit(3) - Determine session, unit, owner of a session, container/VM or slice of a specific PID or socket peer
    sd_pid_notify(3) - Notify service manager about start-up completion and other service status changes
    sd_pid_notifyf(3) - Notify service manager about start-up completion and other service status changes
    sd_pid_notify_with_fds(3) - Notify service manager about start-up completion and other service status changes
    sd_seat_can_graphical(3) - Determine state of a specific seat
    sd_seat_can_multi_session(3) - Determine state of a specific seat
    sd_seat_can_tty(3) - Determine state of a specific seat
    sd_seat_get_active(3) - Determine state of a specific seat
    sd_seat_get_sessions(3) - Determine state of a specific seat
    sd_session_get_class(3) - Determine state of a specific session
    sd_session_get_desktop(3) - Determine state of a specific session
    sd_session_get_display(3) - Determine state of a specific session
    sd_session_get_remote_host(3) - Determine state of a specific session
    sd_session_get_remote_user(3) - Determine state of a specific session
    sd_session_get_seat(3) - Determine state of a specific session
    sd_session_get_service(3) - Determine state of a specific session
    sd_session_get_state(3) - Determine state of a specific session
    sd_session_get_tty(3) - Determine state of a specific session
    sd_session_get_type(3) - Determine state of a specific session
    sd_session_get_uid(3) - Determine state of a specific session
    sd_session_get_vt(3) - Determine state of a specific session
    sd_session_is_active(3) - Determine state of a specific session
    sd_session_is_remote(3) - Determine state of a specific session
    sd_uid_get_display(3) - Determine login state of a specific Unix user ID
    sd_uid_get_seats(3) - Determine login state of a specific Unix user ID
    sd_uid_get_sessions(3) - Determine login state of a specific Unix user ID
    sd_uid_get_state(3) - Determine login state of a specific Unix user ID
    sd_uid_is_on_seat(3) - Determine login state of a specific Unix user ID
    SD_WARNING(3) - APIs for new-style daemons
    sd_warning(3) - APIs for new-style daemons
    sd_watchdog_enabled(3) - Check whether the service manager expects watchdog keep-alive notifications from a service
    search.h(0p) - search tables
    seccomp(2) - operate on Secure Computing state of the process
    seccomp_api_get(3) - Manage the libseccomp API level
    seccomp_api_set(3) - Manage the libseccomp API level
    seccomp_arch_add(3) - Manage seccomp filter architectures
    seccomp_arch_exist(3) - Manage seccomp filter architectures
    seccomp_arch_native(3) - Manage seccomp filter architectures
    seccomp_arch_remove(3) - Manage seccomp filter architectures
    seccomp_arch_resolve_name(3) - Manage seccomp filter architectures
    seccomp_attr_get(3) - Manage the seccomp filter attributes
    seccomp_attr_set(3) - Manage the seccomp filter attributes
    seccomp_export_bpf(3) - Export the seccomp filter
    seccomp_export_pfc(3) - Export the seccomp filter
    seccomp_init(3) - Initialize the seccomp filter state
    seccomp_load(3) - Load the current seccomp filter into the kernel
    seccomp_merge(3) - Merge two seccomp filters
    seccomp_release(3) - Release the seccomp filter state
    seccomp_reset(3) - Initialize the seccomp filter state
    seccomp_rule_add(3) - Add a seccomp filter rule
    seccomp_rule_add_array(3) - Add a seccomp filter rule
    seccomp_rule_add_exact(3) - Add a seccomp filter rule
    seccomp_rule_add_exact_array(3) - Add a seccomp filter rule
    seccomp_syscall_priority(3) - Prioritize syscalls in the seccomp filter
    seccomp_syscall_resolve_name(3) - Resolve a syscall name
    seccomp_syscall_resolve_name_arch(3) - Resolve a syscall name
    seccomp_syscall_resolve_name_rewrite(3) - Resolve a syscall name
    seccomp_syscall_resolve_num_arch(3) - Resolve a syscall name
    seccomp_version(3) - Query the libseccomp version information
    secolor.conf(5) - The SELinux color configuration file
    secon(1) - See an SELinux context, from a file, program or user input.
    secure_getenv(3) - get an environment variable
    securetty(5) - file which lists terminals from which root can log in
    securetty_types(5) - The SELinux secure tty type configuration file
    security(2) - unimplemented system calls
    security_av_perm_to_string(3) - display an access vector in human-readable form.
    security_av_string(3) - display an access vector in human-readable form.
    security_check_context(3) - check the validity of a SELinux context
    security_check_context_raw(3) - check the validity of a SELinux context
    security_class_to_string(3) - display an access vector in human-readable form.
    security_commit_booleans(3) - routines for manipulating SELinux boolean values
    security_compute_av(3) - query the SELinux policy database in the kernel
    security_compute_av_flags(3) - query the SELinux policy database in the kernel
    security_compute_av_flags_raw(3) - query the SELinux policy database in the kernel
    security_compute_av_raw(3) - query the SELinux policy database in the kernel
    security_compute_create(3) - query the SELinux policy database in the kernel
    security_compute_create_name(3) - query the SELinux policy database in the kernel
    security_compute_create_name_raw(3) - query the SELinux policy database in the kernel
    security_compute_create_raw(3) - query the SELinux policy database in the kernel
    security_compute_member(3) - query the SELinux policy database in the kernel
    security_compute_member_raw(3) - query the SELinux policy database in the kernel
    security_compute_relabel(3) - query the SELinux policy database in the kernel
    security_compute_relabel_raw(3) - query the SELinux policy database in the kernel
    security_compute_user(3) - query the SELinux policy database in the kernel
    security_compute_user_raw(3) - query the SELinux policy database in the kernel
    security_deny_unknown(3) - get or set the enforcing state of SELinux
    security_disable(3) - disable the SELinux kernel code at runtime
    security_get_boolean_active(3) - routines for manipulating SELinux boolean values
    security_get_boolean_names(3) - routines for manipulating SELinux boolean values
    security_get_boolean_pending(3) - routines for manipulating SELinux boolean values
    security_getenforce(3) - get or set the enforcing state of SELinux
    security_get_initial_context(3) - query the SELinux policy database in the kernel
    security_get_initial_context_raw(3) - query the SELinux policy database in the kernel
    security_load_booleans(3) - routines for manipulating SELinux boolean values
    security_load_policy(3) - load a new SELinux policy
    security_mkload_policy(3) - load a new SELinux policy
    security_policyvers(3) - get the version of the SELinux policy
    security_set_boolean(3) - routines for manipulating SELinux boolean values
    security_setenforce(3) - get or set the enforcing state of SELinux
    sed(1) - stream editor for filtering and transforming text
    sed(1p) - stream editor
    seed48(3) - generate uniformly distributed pseudo-random numbers
    seed48(3p) - random non-negative long integer generator
    seed48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    seekdir(3) - set the position of the next readdir() call in the directory stream.
    seekdir(3p) - set the position of a directory stream
    sefcontext_compile(8) - compile file context regular expression files
    selabel_close(3) - userspace SELinux labeling interface
    selabel_db(5) - userspace SELinux labeling interface and configuration file format for the RDBMS objects context backend
    selabel_digest(3) - Return digest of specfiles and list of files used
    selabel_file(5) - userspace SELinux labeling interface and configuration file format for the file contexts backend
    selabel_lookup(3) - obtain SELinux security context from a string label
    selabel_lookup_best_match(3) - Only supported on file backend.
    selabel_lookup_best_match_raw(3) - Only supported on file backend.
    selabel_lookup_raw(3) - obtain SELinux security context from a string label
    selabel_media(5) - userspace SELinux labeling interface and configuration file format for the media contexts backend
    selabel_open(3) - userspace SELinux labeling interface
    selabel_partial_match(3) - Only supported on file backend.
    selabel_stats(3) - obtain SELinux labeling statistics
    selabel_x(5) - userspace SELinux labeling interface and configuration file format for the X Window System contexts backend. This backend is also used to determine the default context for labeling remotely connected X clients
    select(2) - synchronous I/O multiplexing
    select(3p) - synchronous I/O multiplexing
    select_tut(2) - synchronous I/O multiplexing
    selinux-polgengui(8) - SELinux Policy Generation Tool
    SELinux(8) - NSA Security-Enhanced Linux (SELinux)
    selinux(8) - NSA Security-Enhanced Linux (SELinux)
    selinux_binary_policy_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_booleans_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_boolean_sub(3) - Search the translated name for a boolean_name record
    selinux_check_access(3) - query the SELinux policy database in the kernel
    selinux_check_passwd_access(3) - query the SELinux policy database in the kernel
    selinux_check_securetty_context(3) - check whether a SELinux tty security context is defined as a securetty context
    selinux_colors_path(3) - Return a path to the active SELinux policy color configuration file
    selinux_config(5) - The SELinux sub-system configuration file.
    selinux_contexts_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_current_policy_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_default_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_default_type_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinuxenabled(8) - tool to be used within shell scripts to determine if selinux is enabled
    selinuxexeccon(8) - report SELinux context used for this executable
    selinux_failsafe_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_file_context_cmp(3) - Compare two SELinux security contexts excluding the 'user' component
    selinux_file_context_homedir_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_file_context_local_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_file_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_file_context_verify(3) - Compare the SELinux security context on disk to the default security context required by the policy file contexts file
    selinux_getenforcemode(3) - get the enforcing state of SELinux
    selinux_getpolicytype(3) - get the type of SELinux policy running on the system
    selinux_homedir_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_init_load_policy(3) - load a new SELinux policy
    selinux_lsetfilecon_default(3) - set the file context to the system defaults
    selinux_media_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_mkload_policy(3) - load a new SELinux policy
    selinux_netfilter_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_policy_root(3) - Set an alternate SELinux root path for the SELinux policy files for this machine.
    selinux_raw_context_to_color(3) - Return RGB color string for an SELinux security context
    selinux_removable_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_restorecon(3) - restore file(s) default SELinux security contexts
    selinux_restorecon_default_handle(3) - sets default parameters for selinux_restorecon(3)
    selinux_restorecon_set_alt_rootpath(3) - set an alternate rootpath.
    selinux_restorecon_set_exclude_list(3) - set list of directories to be excluded from relabeling.
    selinux_restorecon_set_sehandle(3) - set a labeling handle for use by selinux_restorecon(3)
    selinux_restorecon_xattr(3) - manage default security.restorecon_last extended attribute entries added by selinux_restorecon(3), setfiles(8) or restorecon(8).
    selinux_securetty_types_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_set_callback(3) - userspace SELinux callback facilities
    selinux_set_mapping(3) - establish dynamic object class and permission mapping
    selinux_set_policy_root(3) - Set an alternate SELinux root path for the SELinux policy files for this machine.
    selinux_status_close(3) - reference the SELinux kernel status without invocation of system calls
    selinux_status_deny_unknown(3) - reference the SELinux kernel status without invocation of system calls
    selinux_status_getenforce(3) - reference the SELinux kernel status without invocation of system calls
    selinux_status_open(3) - reference the SELinux kernel status without invocation of system calls
    selinux_status_policyload(3) - reference the SELinux kernel status without invocation of system calls
    selinux_status_updated(3) - reference the SELinux kernel status without invocation of system calls
    selinux_user_contexts_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_usersconf_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    selinux_x_context_path(3) - These functions return the paths to the active SELinux policy configuration directories and files
    semanage-boolean(8) - SELinux Policy Management boolean tool
    semanage-dontaudit(8) - SELinux Policy Management dontaudit tool
    semanage-export(8) - SELinux Policy Management import tool
    semanage-fcontext(8) - SELinux Policy Management file context tool
    semanage-ibendport(8) - SELinux Policy Management ibendport mapping tool
    semanage-ibpkey(8) - SELinux Policy Management ibpkey mapping tool
    semanage-import(8) - SELinux Policy Management import tool
    semanage-interface(8) - SELinux Policy Management network interface tool
    semanage-login(8) - SELinux Policy Management linux user to SELinux User mapping tool
    semanage-module(8) - SELinux Policy Management module mapping tool
    semanage-node(8) - SELinux Policy Management node mapping tool
    semanage-permissive(8) - SELinux Policy Management permissive mapping tool
    semanage-port(8) - SELinux Policy Management port mapping tool
    semanage-user(8) - SELinux Policy Management SELinux User mapping tool
    semanage(8) - SELinux Policy Management tool
    semanage.conf(5) - global configuration file for the SELinux Management library
    semanage_bool(3) - SELinux Policy Booleans Management API
    semanage_bool_count(3) - SELinux Management API
    semanage_bool_count_active(3) - SELinux Management API
    semanage_bool_count_local(3) - SELinux Management API
    semanage_bool_del_local(3) - SELinux Management API
    semanage_bool_exists(3) - SELinux Management API
    semanage_bool_exists_active(3) - SELinux Management API
    semanage_bool_exists_local(3) - SELinux Management API
    semanage_bool_iterate(3) - SELinux Management API
    semanage_bool_iterate_active(3) - SELinux Management API
    semanage_bool_iterate_local(3) - SELinux Management API
    semanage_bool_list(3) - SELinux Lists Management API
    semanage_bool_list_active(3) - SELinux Lists Management API
    semanage_bool_list_local(3) - SELinux Lists Management API
    semanage_bool_modify_local(3) - SELinux Management API
    semanage_bool_query(3) - SELinux Management API
    semanage_bool_query_active(3) - SELinux Management API
    semanage_bool_query_local(3) - SELinux Management API
    semanage_bool_set_active(3) - update an existing SELinux boolean in the currently active policy
    semanage_count(3) - SELinux Management API
    semanage_del(3) - SELinux Management API
    semanage_exists(3) - SELinux Management API
    semanage_fcontext(3) - SELinux File Context Management API
    semanage_fcontext_count(3) - SELinux Management API
    semanage_fcontext_count_local(3) - SELinux Management API
    semanage_fcontext_del_local(3) - SELinux Management API
    semanage_fcontext_exists(3) - SELinux Management API
    semanage_fcontext_exists_local(3) - SELinux Management API
    semanage_fcontext_iterate(3) - SELinux Management API
    semanage_fcontext_iterate_local(3) - SELinux Management API
    semanage_fcontext_list(3) - SELinux Lists Management API
    semanage_fcontext_list_local(3) - SELinux Lists Management API
    semanage_fcontext_modify_local(3) - SELinux Management API
    semanage_fcontext_query(3) - SELinux Management API
    semanage_fcontext_query_local(3) - SELinux Management API
    semanage_iface(3) - SELinux Network Interfaces Management API
    semanage_iface_count(3) - SELinux Management API
    semanage_iface_count_local(3) - SELinux Management API
    semanage_iface_del_local(3) - SELinux Management API
    semanage_iface_exists(3) - SELinux Management API
    semanage_iface_exists_local(3) - SELinux Management API
    semanage_iface_iterate(3) - SELinux Management API
    semanage_iface_iterate_local(3) - SELinux Management API
    semanage_iface_list(3) - SELinux Lists Management API
    semanage_iface_list_local(3) - SELinux Lists Management API
    semanage_iface_modify_local(3) - SELinux Management API
    semanage_iface_query(3) - SELinux Management API
    semanage_iface_query_local(3) - SELinux Management API
    semanage_iterate(3) - SELinux Management API
    semanage_list(3) - SELinux Lists Management API
    semanage_modify(3) - SELinux Management API
    semanage_node(3) - SELinux Network Nodes Management API
    semanage_node_count(3) - SELinux Management API
    semanage_node_count_local(3) - SELinux Management API
    semanage_node_del_local(3) - SELinux Management API
    semanage_node_exists(3) - SELinux Management API
    semanage_node_exists_local(3) - SELinux Management API
    semanage_node_iterate(3) - SELinux Management API
    semanage_node_iterate_local(3) - SELinux Management API
    semanage_node_list(3) - SELinux Lists Management API
    semanage_node_list_local(3) - SELinux Lists Management API
    semanage_node_modify_local(3) - SELinux Management API
    semanage_node_query(3) - SELinux Management API
    semanage_node_query_local(3) - SELinux Management API
    semanage_port(3) - SELinux Network Ports Management API
    semanage_port_count(3) - SELinux Management API
    semanage_port_count_local(3) - SELinux Management API
    semanage_port_del_local(3) - SELinux Management API
    semanage_port_exists(3) - SELinux Management API
    semanage_port_exists_local(3) - SELinux Management API
    semanage_port_iterate(3) - SELinux Management API
    semanage_port_iterate_local(3) - SELinux Management API
    semanage_port_list(3) - SELinux Lists Management API
    semanage_port_list_local(3) - SELinux Lists Management API
    semanage_port_modify_local(3) - SELinux Management API
    semanage_port_query(3) - SELinux Management API
    semanage_port_query_local(3) - SELinux Management API
    semanage_query(3) - SELinux Management API
    semanage_root(3) - SELinux Management API
    semanage_set_root(3) - SELinux Management API
    semanage_seuser(3) - Linux UID to SELinux User Management API
    semanage_seuser_count(3) - SELinux Management API
    semanage_seuser_count_local(3) - SELinux Management API
    semanage_seuser_del_local(3) - SELinux Management API
    semanage_seuser_exists(3) - SELinux Management API
    semanage_seuser_exists_local(3) - SELinux Management API
    semanage_seuser_iterate(3) - SELinux Management API
    semanage_seuser_iterate_local(3) - SELinux Management API
    semanage_seuser_list(3) - SELinux Lists Management API
    semanage_seuser_list_local(3) - SELinux Lists Management API
    semanage_seuser_modify_local(3) - SELinux Management API
    semanage_seuser_query(3) - SELinux Management API
    semanage_seuser_query_local(3) - SELinux Management API
    semanage_user(3) - SELinux User Management API
    semanage_user_count(3) - SELinux Management API
    semanage_user_count_local(3) - SELinux Management API
    semanage_user_del_local(3) - SELinux Management API
    semanage_user_exists(3) - SELinux Management API
    semanage_user_exists_local(3) - SELinux Management API
    semanage_user_iterate(3) - SELinux Management API
    semanage_user_iterate_local(3) - SELinux Management API
    semanage_user_list(3) - SELinux Lists Management API
    semanage_user_list_local(3) - SELinux Lists Management API
    semanage_user_modify_local(3) - SELinux Management API
    semanage_user_query(3) - SELinux Management API
    semanage_user_query_local(3) - SELinux Management API
    semaphore.h(0p) - semaphores
    sem_close(3) - close a named semaphore
    sem_close(3p) - close a named semaphore
    semctl(2) - System V semaphore control operations
    semctl(3p) - XSI semaphore control operations
    sem_destroy(3) - destroy an unnamed semaphore
    sem_destroy(3p) - destroy an unnamed semaphore
    semget(2) - get a System V semaphore set identifier
    semget(3p) - get set of XSI semaphores
    sem_getvalue(3) - get the value of a semaphore
    sem_getvalue(3p) - get the value of a semaphore
    sem_init(3) - initialize an unnamed semaphore
    sem_init(3p) - initialize an unnamed semaphore
    semodule(8) - Manage SELinux policy modules.
    semodule_expand(8) - Expand a SELinux policy module package.
    semodule_link(8) - Link SELinux policy module packages together
    semodule_package(8) - Create a SELinux policy module package.
    semodule_unpackage(8) - Extract policy module and file context file from an SELinux policy module package.
    semop(2) - System V semaphore operations
    semop(3p) - XSI semaphore operations
    sem_open(3) - initialize and open a named semaphore
    sem_open(3p) - initialize and open a named semaphore
    sem_overview(7) - overview of POSIX semaphores
    sem_post(3) - unlock a semaphore
    sem_post(3p) - unlock a semaphore
    semtimedop(2) - System V semaphore operations
    sem_timedwait(3) - lock a semaphore
    sem_timedwait(3p) - lock a semaphore
    sem_trywait(3) - lock a semaphore
    sem_trywait(3p) - lock a semaphore
    sem_unlink(3) - remove a named semaphore
    sem_unlink(3p) - remove a named semaphore
    sem_wait(3) - lock a semaphore
    sem_wait(3p) - lock a semaphore
    send(2) - send a message on a socket
    send(3p) - send a message on a socket
    sendfile(2) - transfer data between file descriptors
    sendfile64(2) - transfer data between file descriptors
    sendmmsg(2) - send multiple messages on a socket
    sendmsg(2) - send a message on a socket
    sendmsg(3p) - send a message on a socket using a message structure
    sendto(2) - send a message on a socket
    sendto(3p) - send a message on a socket
    sepermit.conf(5) - configuration file for the pam_sepermit module
    sepgsql_contexts(5) - userspace SELinux labeling interface and configuration file format for the RDBMS objects context backend
    sepol_check_context(3) - Check the validity of a security context against a binary policy.
    sepolgen(8) - Generate an initial SELinux policy module template.
    sepol_genbools(3) - Rewrite a binary policy with different boolean settings
    sepol_genusers(3) - Generate a new binary policy image with a customized user configuration
    sepolicy-booleans(8) - Query SELinux Policy to see description of booleans
    sepolicy-communicate(8) - Generate a report showing if two SELinux Policy Domains can communicate
    sepolicy-generate(8) - Generate an initial SELinux policy module template.
    sepolicy-gui(8) - Graphical User Interface for SELinux policy.
    sepolicy-interface(8) - Print interface information based on the installed SELinux Policy
    sepolicy-manpage(8) - Generate a man page based on the installed SELinux Policy
    sepolicy-network(8) - Examine the SELinux Policy and generate a network report
    sepolicy-transition(8) - Examine the SELinux Policy and generate a process transition report
    sepolicy(8) - SELinux Policy Inspection tool
    seq(1) - print a sequence of numbers
    services(5) - Internet network services list
    service_seusers(5) - The SELinux GNU/Linux user and service to SELinux user mapping configuration files
    session-keyring(7) - session shared process keyring
    sestatus(8) - SELinux status tool
    sestatus.conf(5) - The sestatus(8) configuration file.
    set(1p) - set or unset options and positional parameters
    setaliasent(3) - read an alias entry
    setarch(8) - change reported architecture in new program environment and/or set personality flags
    set_aumessage_mode(3) - Sets the message mode
    setbuf(3) - stream buffering operations
    setbuf(3p) - assign buffering to a stream
    setbuffer(3) - stream buffering operations
    setcap(8) - set file capabilities
    setcchar(3x) - Get a wide character string and rendition from a cchar_t or set a cchar_t from a wide-character string
    setcon(3) - get SELinux security context of a process
    setcon_raw(3) - get SELinux security context of a process
    setcontext(2) - get or set the user context
    setcontext(3) - get or set the user context
    set_curterm(3x) - curses interfaces to terminfo database
    setdomainname(2) - get/set NIS domain name
    setegid(2) - set effective user or group ID
    setegid(3p) - set the effective group ID
    setenforce(8) - modify the mode SELinux is running in
    setenv(3) - change or add an environment variable
    setenv(3p) - add or change environment variable
    seteuid(2) - set effective user or group ID
    seteuid(3p) - set effective user ID
    setexeccon(3) - get or set the SELinux security context used for executing a new process
    setexeccon_raw(3) - get or set the SELinux security context used for executing a new process
    setfacl(1) - set file access control lists
    setfattr(1) - set extended attributes of filesystem objects
    set_field_just(3x) - retrieve field characteristics
    set_field_opts(3x) - set and get field options
    set_field_userptr(3x) - associate application data with a form field
    setfilecon(3) - set SELinux security context of a file
    setfilecon_raw(3) - set SELinux security context of a file
    setfiles(8) - set SELinux file security contexts.
    setfont(8) - load EGA/VGA console screen font
    set_form_opts(3x) - set and get form options
    set_form_userptr(3x) - associate application data with a form item
    __setfpucw(3) - set FPU control word on i386 architecture (obsolete)
    setfscreatecon(3) - get or set the SELinux security context used for creating a new file system object
    setfscreatecon_raw(3) - get or set the SELinux security context used for creating a new file system object
    setfsent(3) - handle fstab entries
    setfsgid(2) - set group identity used for filesystem checks
    setfsgid32(2) - set group identity used for filesystem checks
    setfsuid(2) - set user identity used for filesystem checks
    setfsuid32(2) - set user identity used for filesystem checks
    setgid(2) - set group identity
    setgid(3p) - group-ID
    setgid32(2) - set group identity
    setgrent(3) - get group file entry
    setgrent(3p) - reset the group database to the first entry
    setgroups(2) - get/set list of supplementary group IDs
    setgroups32(2) - get/set list of supplementary group IDs
    sethostent(3) - get network host entry
    sethostent(3p) - network host database functions
    sethostid(2) - get or set the unique identifier of the current host
    sethostid(3) - get or set the unique identifier of the current host
    sethostname(2) - get/set hostname
    set_item_opts(3x) - set and get menu item options
    set_item_userptr(3x) - associate application data with a menu item
    set_item_value(3x) - set and get menu item values
    setitimer(2) - get or set value of an interval timer
    setitimer(3p) - set the value of an interval timer
    setjmp(3) - performing a nonlocal goto
    setjmp(3p) - local goto
    _setjmp(3p) - local goto
    setjmp.h(0p) - stack environment declarations
    setkey(3) - encrypt 64-bit messages
    setkey(3p) - set encoding key (CRYPT)
    setkeycodes(8) - load kernel scancode-to-keycode mapping table entries
    setkeycreatecon(3) - get or set the SELinux security context used for creating a new kernel keyrings
    setkeycreatecon_raw(3) - get or set the SELinux security context used for creating a new kernel keyrings
    setkey_r(3) - encrypt 64-bit messages
    setleds(1) - set the keyboard leds
    setlinebuf(3) - stream buffering operations
    setlocale(3) - set the current locale
    setlocale(3p) - set program locale
    setlogmask(3) - set log priority mask
    setlogmask(3p) - set the log priority mask
    set_matchpathcon_flags(3) - set flags controlling the operation of matchpathcon or matchpathcon_index and configure the behaviour of validity checking and error displaying
    set_matchpathcon_invalidcon(3) - set flags controlling the operation of matchpathcon or matchpathcon_index and configure the behaviour of validity checking and error displaying
    set_matchpathcon_printf(3) - set flags controlling the operation of matchpathcon or matchpathcon_index and configure the behaviour of validity checking and error displaying
    set_mempolicy(2) - set default NUMA memory policy for a thread and its children
    set_menu_back(3x) - color and attribute control for menus
    set_menu_fore(3x) - color and attribute control for menus
    set_menu_format(3x) - set and get menu sizes
    set_menu_grey(3x) - color and attribute control for menus
    set_menu_items(3x) - make and break connections between items and menus
    set_menu_mark(3x) - get and set the menu mark string
    set_menu_opts(3x) - set and get menu options
    set_menu_pad(3x) - color and attribute control for menus
    set_menu_pattern(3x) - set and get a menu's pattern buffer
    set_menu_spacing(3x) - set and get spacing between menu items.
    set_menu_userptr(3x) - associate application data with a menu item
    set_message_mode(3) - Sets the message mode
    setmetamode(1) - define the keyboard meta key handling
    setmntent(3) - get filesystem descriptor file entry
    setnetent(3) - get network entry
    setnetent(3p) - network database function
    setnetgrent(3) - handle network group entries
    set_new_page(3x) - form pagination functions
    setns(2) - reassociate thread with a namespace
    setpci(8) - configure PCI devices
    setpgid(2) - set/get process group
    setpgid(3p) - set process group ID for job control
    setpgrp(2) - set/get process group
    setpgrp(3p) - set the process group ID
    setpriority(2) - get/set program scheduling priority
    setpriority(3p) - set the nice value
    setpriv(1) - run a program with different Linux privilege settings
    setprotoent(3) - get protocol entry
    setprotoent(3p) - network protocol database functions
    setpwent(3) - get password file entry
    setpwent(3p) - user database function
    setquota(8) - set disk quotas
    setrans.conf(8) - translation configuration file for MCS/MLS SELinux systems
    setregid(2) - set real and/or effective user or group ID
    setregid(3p) - set real and effective group IDs
    setregid32(2) - set real and/or effective user or group ID
    setresgid(2) - set real, effective and saved user or group ID
    setresgid32(2) - set real, effective and saved user or group ID
    setresuid(2) - set real, effective and saved user or group ID
    setresuid32(2) - set real, effective and saved user or group ID
    setreuid(2) - set real and/or effective user or group ID
    setreuid(3p) - set real and effective user IDs
    setreuid32(2) - set real and/or effective user or group ID
    setrlimit(2) - get/set resource limits
    setrlimit(3p) - control maximum resource consumption
    set_robust_list(2) - get/set list of robust futexes
    setrpcent(3) - get RPC entry
    setscrreg(3x) - curses output options
    setsebool(8) - set SELinux boolean value
    set_selinuxmnt(3) - initialize the global variable selinux_mnt
    setservent(3) - get service entry
    setservent(3p) - network services database functions
    setsid(1) - run a program in a new session
    setsid(2) - creates a session and sets the process group ID
    setsid(3p) - create session and set process group ID
    setsockcreatecon(3) - get or set the SELinux security context used for creating a new labeled sockets
    setsockcreatecon_raw(3) - get or set the SELinux security context used for creating a new labeled sockets
    setsockopt(2) - get and set options on sockets
    setsockopt(3p) - set the socket options
    setspent(3) - get shadow password file entry
    setstate(3) - random number generator
    setstate(3p) - random number generator state arrays
    setstate_r(3) - reentrant random number generator
    setsyx(3x) - low-level curses routines
    setterm(1) - set terminal attributes
    setterm(3x) - curses interfaces to terminfo database
    set_term(3x) - curses screen initialization and manipulation routines
    set_thread_area(2) - set a GDT entry for thread-local storage
    set_tid_address(2) - set pointer to thread ID
    settimeofday(2) - get / set time
    setttyent(3) - get ttys file entry
    setuid(2) - set user identity
    setuid(3p) - set user ID
    setuid32(2) - set user identity
    setup(2) - setup devices and filesystems, mount root filesystem
    setupterm(3x) - curses interfaces to terminfo database
    setusershell(3) - get permitted user shells
    setutent(3) - access utmp file entries
    setutxent(3) - access utmp file entries
    setutxent(3p) - reset the user accounting database to the first entry
    setvbuf(3) - stream buffering operations
    setvbuf(3p) - assign buffering to a stream
    setvtrgb(8) - set the virtual terminal RGB colors
    setxattr(2) - set an extended attribute value
    seunshare(8) - Run cmd with alternate homedir, tmpdir and/or SELinux context
    seusers(5) - The SELinux GNU/Linux user to SELinux user mapping configuration file
    sfb(8) - Stochastic Fair Blue
    sfdisk(8) - display or manipulate a disk partition table
    sfq(8) - Stochastic Fairness Queueing
    sftp-server(8) - SFTP server subsystem
    sftp(1) - secure file transfer program
    sg(1) - execute command as different group ID
    sgetmask(2) - manipulation of signal mask (obsolete)
    sgetspent(3) - get shadow password file entry
    sgetspent_r(3) - get shadow password file entry
    sh(1p) - shell, the standard command language interpreter
    sha1sum(1) - compute and check SHA1 message digest
    sha224sum(1) - compute and check SHA224 message digest
    sha256sum(1) - compute and check SHA256 message digest
    sha384sum(1) - compute and check SHA384 message digest
    sha512sum(1) - compute and check SHA512 message digest
    shadow(3) - encrypted password file routines
    shadow(5) - shadowed password file
    sheet2pcp(1) - import spreadsheet data and create a PCP archive
    shells(5) - pathnames of valid login shells
    shift(1p) - shift positional parameters
    shmat(2) - System V shared memory operations
    shmat(3p) - XSI shared memory attach operation
    shmctl(2) - System V shared memory control
    shmctl(3p) - XSI shared memory control operations
    shmdt(2) - System V shared memory operations
    shmdt(3p) - XSI shared memory detach operation
    shmget(2) - allocates a System V shared memory segment
    shmget(3p) - get an XSI shared memory segment
    shmop(2) - System V shared memory operations
    shm_open(3) - create/open or unlink POSIX shared memory objects
    shm_open(3p) - open a shared memory object (REALTIME)
    shm_overview(7) - overview of POSIX shared memory
    shm_unlink(3) - create/open or unlink POSIX shared memory objects
    shm_unlink(3p) - remove a shared memory object (REALTIME)
    show-changed-rco(1) - show changes in an RPM package
    show-installed(1) - show installed RPM packages and descriptions
    showconsolefont(8) - Show the current EGA/VGA console screen font
    showkey(1) - examine the codes sent by the keyboard
    showmount(8) - show mount information for an NFS server
    shred(1) - overwrite a file to hide its contents, and optionally delete it
    shuf(1) - generate random permutations
    shutdown(2) - shut down part of a full-duplex connection
    shutdown(3p) - shut down socket send and receive operations
    shutdown(8) - Halt, power-off or reboot the machine
    sidget(3) - obtain and manipulate SELinux security ID's
    sidput(3) - obtain and manipulate SELinux security ID's
    sigaction(2) - examine and change a signal action
    sigaction(3p) - examine and change a signal action
    sigaddset(3) - POSIX signal set operations
    sigaddset(3p) - add a signal to a signal set
    sigaltstack(2) - set and/or get signal stack context
    sigaltstack(3p) - set and get signal alternate stack context
    sigandset(3) - POSIX signal set operations
    sigblock(3) - BSD signal API
    sigdelset(3) - POSIX signal set operations
    sigdelset(3p) - delete a signal from a signal set
    sigemptyset(3) - POSIX signal set operations
    sigemptyset(3p) - initialize and empty a signal set
    sigevent(7) - structure for notification from asynchronous routines
    sigfillset(3) - POSIX signal set operations
    sigfillset(3p) - initialize and fill a signal set
    siggetmask(3) - BSD signal API
    sighold(3) - System V signal API
    sighold(3p) - signal management
    sigignore(3) - System V signal API
    sigignore(3p) - signal management
    siginterrupt(3) - allow signals to interrupt system calls
    siginterrupt(3p) - allow signals to interrupt functions
    sigisemptyset(3) - POSIX signal set operations
    sigismember(3) - POSIX signal set operations
    sigismember(3p) - test for a signal in a signal set
    siglongjmp(3) - performing a nonlocal goto
    siglongjmp(3p) - local goto with signal handling
    sigmask(3) - BSD signal API
    signal-safety(7) - async-signal-safe functions
    signal(2) - ANSI C signal handling
    signal(3p) - signal management
    signal(7) - overview of signals
    signal.h(0p) - signals
    signal_add(3) - execute a function when a specific event occurs
    signal_del(3) - execute a function when a specific event occurs
    signalfd(2) - create a file descriptor for accepting signals
    signalfd4(2) - create a file descriptor for accepting signals
    signal_initialized(3) - execute a function when a specific event occurs
    signal_pending(3) - execute a function when a specific event occurs
    signal_set(3) - execute a function when a specific event occurs
    signbit(3) - test sign of a real floating-point number
    signbit(3p) - test sign
    signgam(3) - log gamma function
    signgam(3p) - log gamma function
    significand(3) - get mantissa of floating-point number
    significandf(3) - get mantissa of floating-point number
    significandl(3) - get mantissa of floating-point number
    sigorset(3) - POSIX signal set operations
    sigpause(3) - atomically release blocked signals and wait for interrupt
    sigpause(3p) - remove a signal from the signal mask and suspend the thread
    sigpending(2) - examine pending signals
    sigpending(3p) - examine pending signals
    sigprocmask(2) - examine and change blocked signals
    sigprocmask(3p) - examine and change blocked signals
    sigqueue(2) - queue a signal and data to a process
    sigqueue(3) - queue a signal and data to a process
    sigqueue(3p) - queue a signal to a process
    sigrelse(3) - System V signal API
    sigrelse(3p) - signal management
    sigreturn(2) - return from signal handler and cleanup stack frame
    sigset(3) - System V signal API
    sigset(3p) - signal management
    sigsetjmp(3) - performing a nonlocal goto
    sigsetjmp(3p) - local goto
    sigsetmask(3) - BSD signal API
    sigsetops(3) - POSIX signal set operations
    sigstack(3) - set and/or get signal stack context
    sigsuspend(2) - wait for a signal
    sigsuspend(3p) - wait for a signal
    sigtimedwait(2) - synchronously wait for queued signals
    sigtimedwait(3p) - wait for queued signals
    sigvec(3) - BSD signal API
    sigwait(3) - wait for a signal
    sigwait(3p) - wait for queued signals
    sigwaitinfo(2) - synchronously wait for queued signals
    sigwaitinfo(3p) - wait for queued signals
    simple(8) - basic example action
    sin(3) - sine function
    sin(3p) - sine function
    sincos(3) - calculate sin and cos simultaneously
    sincosf(3) - calculate sin and cos simultaneously
    sincosl(3) - calculate sin and cos simultaneously
    sinf(3) - sine function
    sinf(3p) - sine function
    sinh(3) - hyperbolic sine function
    sinh(3p) - hyperbolic sine functions
    sinhf(3) - hyperbolic sine function
    sinhf(3p) - hyperbolic sine functions
    sinhl(3) - hyperbolic sine function
    sinhl(3p) - hyperbolic sine functions
    sinl(3) - sine function
    sinl(3p) - sine function
    size(1) - list section sizes and total size.
    sk98lin(4) - Marvell/SysKonnect Gigabit Ethernet driver v6.21
    skbedit(8) - SKB editing action
    skbmod(8) - user-friendly packet editor action
    skbprio(8) - SKB Priority Queue
    skill(1) - send a signal or report process status
    slabinfo(5) - kernel slab allocator statistics
    slabtop(1) - display kernel slab cache information in real time
    slapacl(8) - Check access to a list of attributes.
    slapadd(8) - Add entries to a SLAPD database
    slapauth(8) - Check a list of string-represented IDs for LDAP authc/authz
    slapcat(8) - SLAPD database to LDIF utility
    slapd-asyncmeta(5) - asynchronous metadirectory backend to slapd
    slapd-bdb(5) - Berkeley DB backends to slapd
    slapd-config(5) - configuration backend to slapd
    slapd-dnssrv(5) - DNS SRV referral backend to slapd
    slapd-hdb(5) - Berkeley DB backends to slapd
    slapd-ldap(5) - LDAP backend to slapd
    slapd-ldif(5) - LDIF backend to slapd
    slapd-mdb(5) - Memory-Mapped DB backend to slapd
    slapd-meta(5) - metadirectory backend to slapd
    slapd-monitor(5) - Monitor backend to slapd
    slapd-ndb(5) - MySQL NDB backend to slapd
    slapd-null(5) - Null backend to slapd
    slapd-passwd(5) - /etc/passwd backend to slapd
    slapd-perl(5) - Perl backend to slapd
    slapd-relay(5) - relay backend to slapd
    slapd-shell(5) - Shell backend to slapd
    slapd-sock(5) - Socket backend/overlay to slapd
    slapd-sql(5) - SQL backend to slapd
    slapd-wt(5) - WiredTiger backend to slapd
    slapd(8) - Stand-alone LDAP Daemon
    slapd.access(5) - access configuration for slapd, the stand-alone LDAP daemon
    slapd.backends(5) - backends for slapd, the stand-alone LDAP daemon
    slapd.conf(5) - configuration file for slapd, the stand-alone LDAP daemon
    slapd.overlays(5) - overlays for slapd, the stand-alone LDAP daemon
    slapd.plugin(5) - plugin configuration for slapd, the stand-alone LDAP daemon
    slapdn(8) - Check a list of string-represented LDAP DNs based on schema syntax
    slapindex(8) - Reindex entries in a SLAPD database
    slapmodify(8) - Modify entries in a SLAPD database
    slapo-accesslog(5) - Access Logging overlay to slapd
    slapo-auditlog(5) - Audit Logging overlay to slapd
    slapo-autoca(5) - Automatic Certificate Authority overlay to slapd
    slapo-chain(5) - chain overlay to slapd
    slapo-collect(5) - Collective attributes overlay to slapd
    slapo-constraint(5) - Attribute Constraint Overlay to slapd
    slapo-dds(5) - Dynamic Directory Services overlay to slapd
    slapo-dyngroup(5) - Dynamic Group overlay to slapd
    slapo-dynlist(5) - Dynamic List overlay to slapd
    slapo-memberof(5) - Reverse Group Membership overlay to slapd
    slapo-pbind(5) - proxy bind overlay to slapd
    slapo-pcache(5) - proxy cache overlay to slapd
    slapo-ppolicy(5) - Password Policy overlay to slapd
    slapo-refint(5) - Referential Integrity overlay to slapd
    slapo-retcode(5) - return code overlay to slapd
    slapo-rwm(5) - rewrite/remap overlay to slapd
    slapo-sock(5) - Socket backend/overlay to slapd
    slapo-sssvlv(5) - Server Side Sorting and Virtual List View overlay to slapd
    slapo-syncprov(5) - Sync Provider overlay to slapd
    slapo-translucent(5) - Translucent Proxy overlay to slapd
    slapo-unique(5) - Attribute Uniqueness overlay to slapd
    slapo-valsort(5) - Value Sorting overlay to slapd
    slappasswd(8) - OpenLDAP password utility
    slapschema(8) - SLAPD in-database schema checking utility
    slaptest(8) - Check the suitability of the OpenLDAP slapd configuration
    slattach(8) - attach a network interface to a serial line
    sleep(1) - delay for a specified amount of time
    sleep(1p) - suspend execution for an interval
    sleep(3) - sleep for a specified number of seconds
    sleep(3p) - suspend execution for an interval of time
    sleep.conf.d(5) - Suspend and hibernation configuration file
    SLIST_EMPTY(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_empty(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_ENTRY(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_entry(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_FIRST(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_first(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_FOREACH(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_foreach(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_HEAD_INITIALIZER(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_head_initializer(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_INIT(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_init(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_INSERT_AFTER(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_insert_after(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_INSERT_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_insert_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_NEXT(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_next(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_REMOVE(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_remove(3) - linked lists, singly-linked tail queues, lists and tail queues
    SLIST_REMOVE_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    slist_remove_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    slk_attr(3x) - curses soft label routines
    slk_attroff(3x) - curses soft label routines
    slk_attr_off(3x) - curses soft label routines
    slk_attron(3x) - curses soft label routines
    slk_attr_on(3x) - curses soft label routines
    slk_attrset(3x) - curses soft label routines
    slk_attr_set(3x) - curses soft label routines
    slk_clear(3x) - curses soft label routines
    slk_color(3x) - curses soft label routines
    slk_init(3x) - curses soft label routines
    slk_label(3x) - curses soft label routines
    slk_noutrefresh(3x) - curses soft label routines
    slk_refresh(3x) - curses soft label routines
    slk_restore(3x) - curses soft label routines
    slk_set(3x) - curses soft label routines
    slk_touch(3x) - curses soft label routines
    slk_wset(3x) - curses soft label routines
    sln(8) - create symbolic links
    sm-notify(8) - send reboot notifications to NFS peers
    smartpqi(4) - Microsemi Smart Family SCSI driver
    smem(8) - Report memory usage with shared memory divided proportionally.
    snice(1) - send a signal or report process status
    snmp(8) - cups snmp backend
    snmp.conf(5) - snmp configuration file for cups
    snprintf(3) - formatted output conversion
    snprintf(3p) - print formatted output
    sockatmark(3) - determine whether socket is at out-of-band mark
    sockatmark(3p) - of-band mark
    Sockbuf_IO(3) - OpenLDAP LBER I/O infrastructure
    sock_diag(7) - obtaining information about sockets
    socket(2) - create an endpoint for communication
    socket(3p) - create an endpoint for communication
    socket(7) - Linux socket interface
    socketcall(2) - socket system calls
    socketpair(2) - create a pair of connected sockets
    socketpair(3p) - create a pair of connected sockets
    soelim(1) - interpret .so requests in groff input
    sort(1) - sort lines of text files
    sort(1p) - sort, merge, or sequence check text files
    SP(3x) - curses terminfo global variables
    sparse(1) - Semantic Parser for C
    spawn.h(0p) - spawn (ADVANCED REALTIME)
    splice(2) - splice data to/from a pipe
    split(1) - split a file into pieces
    split(1p) - split files into pieces
    sprintf(3) - formatted output conversion
    sprintf(3p) - print formatted output
    sprof(1) - read and display shared object profiling data
    spu_create(2) - create a new spu context
    spufs(7) - SPU filesystem
    spu_run(2) - execute an SPU context
    sqrt(3) - square root function
    sqrt(3p) - square root function
    sqrtf(3) - square root function
    sqrtf(3p) - square root function
    sqrtl(3) - square root function
    sqrtl(3p) - square root function
    srand(3) - pseudo-random number generator
    srand(3p) - random number generator
    srand48(3) - generate uniformly distributed pseudo-random numbers
    srand48(3p) - precision pseudo-random number generator
    srand48_r(3) - generate uniformly distributed pseudo-random numbers reentrantly
    srandom(3) - random number generator
    srandom(3p) - random number generator
    srandom_r(3) - reentrant random number generator
    srp_daemon.service(5) - srp_daemon systemd service that controls all ports
    srp_daemon_port.service(5) - srp_daemon_port@ systemd service that controls a single port
    srp_daemon_port@.service(5) - srp_daemon_port@ systemd service that controls a single port
    srptool(1) - GnuTLS SRP tool
    ss(8) - another utility to investigate sockets
    sscanf(3) - input format conversion
    sscanf(3p) - convert formatted input
    ssetmask(2) - manipulation of signal mask (obsolete)
    ssh-add(1) - adds private key identities to the authentication agent
    ssh-agent(1) - authentication agent
    ssh-keygen(1) - authentication key generation, management and conversion
    ssh-keyscan(1) - gather SSH public keys
    ssh-keysign(8) - ssh helper program for host-based authentication
    ssh-pkcs11-helper(8) - ssh-agent helper program for PKCS#11 support
    ssh(1) - OpenSSH SSH client (remote login program)
    ssh_config(5) - OpenSSH SSH client configuration files
    sshd(8) - OpenSSH SSH daemon
    sshd_config(5) - OpenSSH SSH daemon configuration file
    SSHFS(1) - filesystem client based on ssh
    sshfs(1) - filesystem client based on ssh
    ssignal(3) - software signal facility
    st(4) - SCSI tape device
    STAILQ_CONCAT(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_concat(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_EMPTY(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_empty(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_ENTRY(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_entry(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_FIRST(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_first(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_FOREACH(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_foreach(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_HEAD_INITIALIZER(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_head_initializer(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_INIT(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_init(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_INSERT_AFTER(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_insert_after(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_INSERT_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_insert_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_INSERT_TAIL(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_insert_tail(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_NEXT(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_next(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_REMOVE(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_remove(3) - linked lists, singly-linked tail queues, lists and tail queues
    STAILQ_REMOVE_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    stailq_remove_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    standards(7) - C and UNIX Standards
    standend(3x) - curses character and window attribute control routines
    standout(3x) - curses character and window attribute control routines
    stap-exporter(8) - systemtap-prometheus interoperation mechanism
    stap-merge(1) - systemtap per-cpu binary merger
    stap-prep(1) - prepare system for systemtap use
    stap-report(1) - collect system information that is useful for debugging systemtap bugs
    stap-server(8) - systemtap compile server management
    stap(1) - systemtap script translator/driver
    stapbpf(8) - systemtap bpf runtime
    stapdyn(8) - systemtap dyninst runtime
    stapex(3stap) - systemtap examples
    stapfuncs(3stap) - systemtap functions
    stappaths(7) - systemtap configurable file paths
    stapprobes(3stap) - systemtap probe points
    stapref(1) - systemtap language reference
    staprun(8) - systemtap runtime
    stapsh(8) - stapsh
    stapvars(3stap) - systemtap variables
    stapvirt(1) - prepare libvirt domains for systemtap probing
    start-stop-daemon(8) - start and stop system daemon programs
    start_color(3x) - curses color manipulation routines
    stat(1) - display file or file system status
    stat(2) - get file status
    stat(3p) - get file status
    stat64(2) - get file status
    statd(8) - NSM service daemon
    statfs(2) - get filesystem statistics
    statfs64(2) - get filesystem statistics
    statvfs(2) - get filesystem statistics
    statvfs(3) - get filesystem statistics
    statvfs(3p) - get file system information
    statx(2) - get file status (extended)
    stdarg(3) - variable argument lists
    stdarg.h(0p) - handle variable argument list
    stdbool.h(0p) - boolean type and values
    stdbuf(1) - Run COMMAND, with modified buffering operations for its standard streams.
    stddef.h(0p) - standard type definitions
    stderr(3) - standard I/O streams
    stderr(3p) - standard I/O streams
    stdin(3) - standard I/O streams
    stdin(3p) - standard I/O streams
    stdint.h(0p) - integer types
    stdio(3) - standard input/output library functions
    stdio.h(0p) - standard buffered input/output
    stdio_ext(3) - interfaces to stdio FILE structure
    stdlib.h(0p) - standard library definitions
    stdout(3) - standard I/O streams
    stdout(3p) - standard I/O streams
    stdscr(3x) - curses global variables
    stg-branch(1) - Branch operations: switch, list, create, rename, delete, ...
    stg-clean(1) - Delete the empty patches in the series
    stg-clone(1) - Make a local clone of a remote repository
    stg-commit(1) - Permanently store the applied patches into the stack base
    stg-delete(1) - Delete patches
    stg-diff(1) - Show the tree diff
    stg-edit(1) - Edit a patch description or diff
    stg-export(1) - Export patches to a directory
    stg-files(1) - Show the files modified by a patch (or the current patch)
    stg-float(1) - Push patches to the top, even if applied
    stg-fold(1) - Integrate a GNU diff patch into the current patch
    stg-goto(1) - Push or pop patches to the given one
    stg-hide(1) - Hide a patch in the series
    stg-id(1) - Print the git hash value of a StGit reference
    stg-import(1) - Import a GNU diff file as a new patch
    stg-init(1) - Initialise the current branch for use with StGIT
    stg-log(1) - Display the patch changelog
    stg-mail(1) - Send a patch or series of patches by e-mail
    stg-new(1) - Create a new, empty patch
    stg-next(1) - Print the name of the next patch
    stg-patches(1) - Show the applied patches modifying a file
    stg-pick(1) - Import a patch from a different branch or a commit object
    stg-pop(1) - Pop one or more patches from the stack
    stg-prev(1) - Print the name of the previous patch
    stg-publish(1) - Push the stack changes to a merge-friendly branch
    stg-pull(1) - Pull changes from a remote repository
    stg-push(1) - Push one or more patches onto the stack
    stg-rebase(1) - Move the stack base to another point in history
    stg-redo(1) - Undo the last undo operation
    stg-refresh(1) - Generate a new commit for the current patch
    stg-rename(1) - Rename a patch
    stg-repair(1) - Fix StGit metadata if branch was modified with git commands
    stg-reset(1) - Reset the patch stack to an earlier state
    stg-series(1) - Print the patch series
    stg-show(1) - Show the commit corresponding to a patch
    stg-sink(1) - Send patches deeper down the stack
    stg-squash(1) - Squash two or more patches into one
    stg-sync(1) - Synchronise patches with a branch or a series
    stg-top(1) - Print the name of the top patch
    stg-uncommit(1) - Turn regular git commits into StGit patches
    stg-undo(1) - Undo the last operation
    stg-unhide(1) - Unhide a hidden patch
    stg(1) - Manage stacks of patches using the Git content tracker
    stime(2) - set time
    stpcpy(3) - copy a string returning a pointer to its end
    stpcpy(3p) - copy a string and return a pointer to the end of the result
    stpncpy(3) - copy a fixed-size string, returning a pointer to its end
    stpncpy(3p) - copy fixed length string, returning a pointer to the array end
    strace(1) - trace system calls and signals
    strcasecmp(3) - compare two strings ignoring case
    strcasecmp(3p) - insensitive string comparisons
    strcasecmp_l(3p) - insensitive string comparisons
    strcasestr(3) - locate a substring
    strcat(3) - concatenate two strings
    strcat(3p) - concatenate two strings
    strchr(3) - locate character in string
    strchr(3p) - string scanning operation
    strchrnul(3) - locate character in string
    strcmp(3) - compare two strings
    strcmp(3p) - compare two strings
    strcodes(3x) - curses terminfo global variables
    strcoll(3) - compare two strings using the current locale
    strcoll(3p) - string comparison using collating information
    strcoll_l(3p) - string comparison using collating information
    strcpy(3) - copy a string
    strcpy(3p) - copy a string and return a pointer to the end of the result
    strcspn(3) - get length of a prefix substring
    strcspn(3p) - get the length of a complementary substring
    strdup(3) - duplicate a string
    strdup(3p) - duplicate a specific number of bytes from a string
    strdupa(3) - duplicate a string
    strerror(3) - return string describing error number
    strerror(3p) - get error message string
    strerror_l(3) - return string describing error number
    strerror_l(3p) - get error message string
    strerror_r(3) - return string describing error number
    strerror_r(3p) - get error message string
    strfmon(3) - convert monetary value to a string
    strfmon(3p) - convert monetary value to a string
    strfmon_l(3) - convert monetary value to a string
    strfmon_l(3p) - convert monetary value to a string
    strfnames(3x) - curses terminfo global variables
    strfromd(3) - convert a floating-point value into a string
    strfromf(3) - convert a floating-point value into a string
    strfroml(3) - convert a floating-point value into a string
    strfry(3) - randomize a string
    strftime(3) - format date and time
    strftime(3p) - convert date and time to a string
    strftime_l(3p) - convert date and time to a string
    string(3) - string operations
    string.h(0p) - string operations
    strings(1) - print the strings of printable characters in files.
    strings(1p) - find printable strings in files
    strings.h(0p) - string operations
    string_to_av_perm(3) - display an access vector in human-readable form.
    string_to_security_class(3) - display an access vector in human-readable form.
    strip(1) - Discard symbols from object files.
    strip(1p) - remove unnecessary information from strippable files (DEVELOPMENT)
    strlen(3) - calculate the length of a string
    strlen(3p) - get length of fixed size string
    strnames(3x) - curses terminfo global variables
    strncasecmp(3) - compare two strings ignoring case
    strncasecmp(3p) - insensitive string comparisons
    strncasecmp_l(3p) - insensitive string comparisons
    strncat(3) - concatenate two strings
    strncat(3p) - concatenate a string with part of another
    strncmp(3) - compare two strings
    strncmp(3p) - compare part of two strings
    strncpy(3) - copy a string
    strncpy(3p) - copy fixed length string, returning a pointer to the array end
    strndup(3) - duplicate a string
    strndup(3p) - duplicate a specific number of bytes from a string
    strndupa(3) - duplicate a string
    strnlen(3) - determine the length of a fixed-size string
    strnlen(3p) - get length of fixed size string
    stropts.h(0p) - STREAMS interface (STREAMS)
    strpbrk(3) - search a string for any of a set of bytes
    strpbrk(3p) - scan a string for a byte
    strptime(3) - convert a string representation of time to a time tm structure
    strptime(3p) - date and time conversion
    strrchr(3) - locate character in string
    strrchr(3p) - string scanning operation
    strsep(3) - extract token from string
    strsignal(3) - return string describing signal
    strsignal(3p) - get name of signal
    strspn(3) - get length of a prefix substring
    strspn(3p) - get length of a substring
    strstr(3) - locate a substring
    strstr(3p) - find a substring
    strtod(3) - convert ASCII string to floating-point number
    strtod(3p) - precision number
    strtof(3) - convert ASCII string to floating-point number
    strtof(3p) - precision number
    strtoimax(3) - convert string to integer
    strtoimax(3p) - convert string to integer type
    strtok(3) - extract tokens from strings
    strtok(3p) - split string into tokens
    strtok_r(3) - extract tokens from strings
    strtok_r(3p) - split string into tokens
    strtol(3) - convert a string to a long integer
    strtol(3p) - convert a string to a long integer
    strtold(3) - convert ASCII string to floating-point number
    strtold(3p) - precision number
    strtoll(3) - convert a string to a long integer
    strtoll(3p) - convert a string to a long integer
    strtoq(3) - convert a string to a long integer
    strtoul(3) - convert a string to an unsigned long integer
    strtoul(3p) - convert a string to an unsigned long
    strtoull(3) - convert a string to an unsigned long integer
    strtoull(3p) - convert a string to an unsigned long
    strtoumax(3) - convert string to integer
    strtoumax(3p) - convert a string to an integer type
    strtouq(3) - convert a string to an unsigned long integer
    struct(3) - OpenLDAP LBER types and allocation functions
    strverscmp(3) - compare two version strings
    strxfrm(3) - string transformation
    strxfrm(3p) - string transformation
    strxfrm_l(3p) - string transformation
    stty(1) - change and print terminal line settings
    stty(1p) - set the options for a terminal
    stty(2) - unimplemented system calls
    su(1) - run a command with substitute user and group ID
    suauth(5) - detailed su control file
    subgid(5) - the subordinate gid file
    subpad(3x) - create and display curses pads
    subpage_prot(2) - define a subpage protection for an address range
    subscriptions.conf(5) - subscription configuration file for cups
    subuid(5) - the subordinate uid file
    subwin(3x) - create curses windows
    suffixes(7) - list of file suffixes
    sulogin(8) - single-user login
    sum(1) - checksum and count the blocks in a file
    svc_destroy(3) - library routines for remote procedure calls
    svcerr_auth(3) - library routines for remote procedure calls
    svcerr_decode(3) - library routines for remote procedure calls
    svcerr_noproc(3) - library routines for remote procedure calls
    svcerr_noprog(3) - library routines for remote procedure calls
    svcerr_progvers(3) - library routines for remote procedure calls
    svcerr_systemerr(3) - library routines for remote procedure calls
    svcerr_weakauth(3) - library routines for remote procedure calls
    svcfd_create(3) - library routines for remote procedure calls
    svc_freeargs(3) - library routines for remote procedure calls
    svc_getargs(3) - library routines for remote procedure calls
    svc_getcaller(3) - library routines for remote procedure calls
    svc_getreq(3) - library routines for remote procedure calls
    svc_getreqset(3) - library routines for remote procedure calls
    svcgssd(8) - server-side rpcsec_gss daemon
    svcraw_create(3) - library routines for remote procedure calls
    svc_register(3) - library routines for remote procedure calls
    svc_run(3) - library routines for remote procedure calls
    svc_sendreply(3) - library routines for remote procedure calls
    svctcp_create(3) - library routines for remote procedure calls
    svcudp_bufcreate(3) - library routines for remote procedure calls
    svcudp_create(3) - library routines for remote procedure calls
    svc_unregister(3) - library routines for remote procedure calls
    svipc(7) - System V interprocess communication mechanisms
    swab(3) - swap adjacent bytes
    swab(3p) - swap bytes
    swapcontext(3) - manipulate user context
    swaplabel(8) - print or change the label or UUID of a swap area
    swapoff(2) - start/stop swapping to file/device
    swapoff(8) - enable/disable devices and files for paging and swapping
    swapon(2) - start/stop swapping to file/device
    swapon(8) - enable/disable devices and files for paging and swapping
    switch_root(8) - switch to another filesystem as the root of the mount tree
    swprintf(3) - formatted wide-character output conversion
    swprintf(3p) - character output
    swscanf(3p) - character input
    symlink(2) - make a new name for a file
    symlink(3p) - make a symbolic link relative to directory file descriptor
    symlink(7) - symbolic link handling
    symlinkat(2) - make a new name for a file
    symlinkat(3p) - make a symbolic link relative to directory file descriptor
    sync(1) - Synchronize cached writes to persistent storage
    sync(2) - commit filesystem caches to disk
    sync(3p) - schedule file system updates
    sync_file_range(2) - sync a file segment with disk
    sync_file_range2(2) - sync a file segment with disk
    syncfs(2) - commit filesystem caches to disk
    syncok(3x) - create curses windows
    syscall(2) - indirect system call
    _syscall(2) - invoking a system call without library support (OBSOLETE)
    syscalls(2) - Linux system calls
    sysconf(3) - get configuration information at run time
    sysconf(3p) - get configurable system variables
    sysctl(2) - read/write system parameters
    _sysctl(2) - read/write system parameters
    sysctl(8) - configure kernel parameters at runtime
    sysctl.conf(5) - sysctl preload/configuration file
    sysctl.d(5) - Configure kernel parameters at boot
    sysdig(8) -
    sys_errlist(3) - print a system error message
    sysfs(2) - get filesystem type information
    sysfs(5) - a filesystem for exporting kernel objects
    sysinfo(2) - return system information
    sys_ipc.h(0p) - XSI interprocess communication access structure
    syslog(2) - read and/or clear kernel message ring buffer; set console_loglevel
    syslog(3) - send messages to the system logger
    syslog(3p) - log a message
    syslog.h(0p) - definitions for system error logging
    sys_mman.h(0p) - memory management declarations
    sys_msg.h(0p) - XSI message queue structures
    sys_nerr(3) - print a system error message
    sys_resource.h(0p) - definitions for XSI resource operations
    sys_select.h(0p) - select types
    sys_sem.h(0p) - XSI semaphore facility
    sys_shm.h(0p) - XSI shared memory facility
    sys_socket.h(0p) - main sockets header
    sysstat(5) - sysstat configuration file.
    sys_stat.h(0p) - data returned by the stat() function
    sys_statvfs.h(0p) - VFS File System information structure
    system-config-selinux(8) - SELinux Management tool
    system(3) - execute a shell command
    system(3p) - issue a command
    system.conf.d(5) - System and session service manager configuration files
    systemctl(1) - Control the systemd system and service manager
    systemd-activate(8) - Test socket activation of daemons
    systemd-analyze(1) - Analyze system boot-up performance
    systemd-ask-password-console.path(8) - Query the user for system passwords on the console and via wall
    systemd-ask-password-console.service(8) - Query the user for system passwords on the console and via wall
    systemd-ask-password-wall.path(8) - Query the user for system passwords on the console and via wall
    systemd-ask-password-wall.service(8) - Query the user for system passwords on the console and via wall
    systemd-ask-password(1) - Query the user for a system password
    systemd-backlight(8) - Load and save the display backlight brightness at boot and shutdown
    systemd-backlight.service(8) - Load and save the display backlight brightness at boot and shutdown
    systemd-backlight@.service(8) - Load and save the display backlight brightness at boot and shutdown
    systemd-binfmt(8) - Configure additional binary formats for executables at boot
    systemd-binfmt.service(8) - Configure additional binary formats for executables at boot
    systemd-bootchart(1) - Boot performance graphing tool
    systemd-bus-proxyd(8) - Connect STDIO or a socket to a given bus address
    systemd-bus-proxyd.service(8) - Proxy classic D-Bus clients to kdbus
    systemd-bus-proxyd.socket(8) - Proxy classic D-Bus clients to kdbus
    systemd-cat(1) - Connect a pipeline or program's output with the journal
    systemd-cgls(1) - Recursively show control group contents
    systemd-cgtop(1) - Show top control groups by their resource usage
    systemd-coredump(8) - Acquire, save and process core dumps
    systemd-coredump.service(8) - Acquire, save and process core dumps
    systemd-coredump.socket(8) - Acquire, save and process core dumps
    systemd-coredump@.service(8) - Acquire, save and process core dumps
    systemd-debug-generator(8) - Generator for enabling a runtime debug shell and masking specific units at boot
    systemd-delta(1) - Find overridden configuration files
    systemd-detect-virt(1) - Detect execution in a virtualized environment
    systemd-environment-d-generator(8) - Load variables specified by environment.d
    systemd-escape(1) - Escape strings for usage in system unit names
    systemd-firstboot(1) - Initialize basic system settings on or before the first boot-up of a system
    systemd-firstboot.service(1) - Initialize basic system settings on or before the first boot-up of a system
    systemd-fsck-root.service(8) - File system checker logic
    systemd-fsck(8) - File system checker logic
    systemd-fsck.service(8) - File system checker logic
    systemd-fsck@.service(8) - File system checker logic
    systemd-fstab-generator(8) - Unit generator for /etc/fstab
    systemd-getty-generator(8) - Generator for enabling getty instances on the console
    systemd-gpt-auto-generator(8) - Generator for automatically discovering and mounting root, /home and /srv partitions, as well as discovering and enabling swap partitions, based on GPT partition type GUIDs.
    systemd-halt.service(8) - System shutdown logic
    systemd-hibernate-resume-generator(8) - Unit generator for resume= kernel parameter
    systemd-hibernate-resume(8) - Resume from hibernation
    systemd-hibernate-resume.service(8) - Resume from hibernation
    systemd-hibernate-resume@.service(8) - Resume from hibernation
    systemd-hibernate.service(8) - System sleep state logic
    systemd-hostnamed(8) - Host name bus mechanism
    systemd-hostnamed.service(8) - Host name bus mechanism
    systemd-hwdb(8) - hardware database management tool
    systemd-hybrid-sleep.service(8) - System sleep state logic
    systemd-importd(8) - VM and container image import and export service
    systemd-importd.service(8) - VM and container image import and export service
    systemd-inhibit(1) - Execute a program with an inhibition lock taken
    systemd-initctl(8) - /dev/initctl compatibility
    systemd-initctl.service(8) - /dev/initctl compatibility
    systemd-initctl.socket(8) - /dev/initctl compatibility
    systemd-journald-audit.socket(8) - Journal service
    systemd-journald-dev-log.socket(8) - Journal service
    systemd-journald(8) - Journal service
    systemd-journald.service(8) - Journal service
    systemd-journald.socket(8) - Journal service
    systemd-kexec.service(8) - System shutdown logic
    systemd-localed(8) - Locale bus mechanism
    systemd-localed.service(8) - Locale bus mechanism
    systemd-logind(8) - Login manager
    systemd-logind.service(8) - Login manager
    systemd-machine-id-commit.service(8) - Commit a transient machine ID to disk
    systemd-machine-id-setup(1) - Initialize the machine ID in /etc/machine-id
    systemd-machined(8) - Virtual machine and container registration manager
    systemd-machined.service(8) - Virtual machine and container registration manager
    systemd-modules-load(8) - Load kernel modules at boot
    systemd-modules-load.service(8) - Load kernel modules at boot
    systemd-mount(1) - Establish and destroy transient mount or auto-mount points
    systemd-networkd-wait-online(8) - Wait for network to come online
    systemd-networkd-wait-online.service(8) - Wait for network to come online
    systemd-networkd(8) - Network manager
    systemd-networkd.service(8) - Network manager
    systemd-notify(1) - Notify service manager about start-up completion and other daemon status changes
    systemd-nspawn(1) - Spawn a namespace container for debugging, testing and building
    systemd-path(1) - List and query system and user paths
    systemd-poweroff.service(8) - System shutdown logic
    systemd-quotacheck(8) - File system quota checker logic
    systemd-quotacheck.service(8) - File system quota checker logic
    systemd-random-seed(8) - Load and save the system random seed at boot and shutdown
    systemd-random-seed.service(8) - Load and save the system random seed at boot and shutdown
    systemd-reboot.service(8) - System shutdown logic
    systemd-remount-fs(8) - Remount root and kernel file systems
    systemd-remount-fs.service(8) - Remount root and kernel file systems
    systemd-resolve(1) - Resolve domain names, IPV4 and IPv6 addresses, DNS resource records, and services
    systemd-resolved(8) - Network Name Resolution manager
    systemd-resolved.service(8) - Network Name Resolution manager
    systemd-rfkill(8) - Load and save the RF kill switch state at boot and change
    systemd-rfkill.service(8) - Load and save the RF kill switch state at boot and change
    systemd-rfkill.socket(8) - Load and save the RF kill switch state at boot and change
    systemd-run(1) - Run programs in transient scope units, service units, or timer-scheduled service units
    systemd-shutdown(8) - System shutdown logic
    systemd-sleep(8) - System sleep state logic
    systemd-sleep.conf(5) - Suspend and hibernation configuration file
    systemd-socket-activate(1) - Test socket activation of daemons
    systemd-socket-proxyd(8) - Bidirectionally proxy local sockets to another (possibly remote) socket.
    systemd-suspend.service(8) - System sleep state logic
    systemd-sysctl(8) - Configure kernel parameters at boot
    systemd-sysctl.service(8) - Configure kernel parameters at boot
    systemd-system-update-generator(8) - Generator for redirecting boot to offline update mode
    systemd-system.conf(5) - System and session service manager configuration files
    systemd-sysusers(8) - Allocate system users and groups
    systemd-sysusers.service(8) - Allocate system users and groups
    systemd-sysv-generator(8) - Unit generator for SysV init scripts
    systemd-timedated(8) - Time and date bus mechanism
    systemd-timedated.service(8) - Time and date bus mechanism
    systemd-timesyncd(8) - Network Time Synchronization
    systemd-timesyncd.service(8) - Network Time Synchronization
    systemd-tmpfiles-clean.service(8) - Creates, deletes and cleans up volatile and temporary files and directories
    systemd-tmpfiles-clean.timer(8) - Creates, deletes and cleans up volatile and temporary files and directories
    systemd-tmpfiles-setup-dev.service(8) - Creates, deletes and cleans up volatile and temporary files and directories
    systemd-tmpfiles-setup.service(8) - Creates, deletes and cleans up volatile and temporary files and directories
    systemd-tmpfiles(8) - Creates, deletes and cleans up volatile and temporary files and directories
    systemd-tty-ask-password-agent(1) - List or process pending systemd password requests
    systemd-udevd-control.socket(8) - Device event managing daemon
    systemd-udevd-kernel.socket(8) - Device event managing daemon
    systemd-udevd(8) - Device event managing daemon
    systemd-udevd.service(8) - Device event managing daemon
    systemd-umount(1) - Establish and destroy transient mount or auto-mount points
    systemd-update-done(8) - Mark /etc and /var fully updated
    systemd-update-done.service(8) - Mark /etc and /var fully updated
    systemd-update-utmp-runlevel.service(8) - Write audit and utmp updates at bootup, runlevel changes and shutdown
    systemd-update-utmp(8) - Write audit and utmp updates at bootup, runlevel changes and shutdown
    systemd-update-utmp.service(8) - Write audit and utmp updates at bootup, runlevel changes and shutdown
    systemd-user-sessions(8) - Permit user logins after boot, prohibit user logins at shutdown
    systemd-user-sessions.service(8) - Permit user logins after boot, prohibit user logins at shutdown
    systemd-user.conf(5) - System and session service manager configuration files
    systemd-vconsole-setup(8) - Configure the virtual consoles
    systemd-vconsole-setup.service(8) - Configure the virtual consoles
    systemd-volatile-root(8) - Make the root file system volatile
    systemd-volatile-root.service(8) - Make the root file system volatile
    systemd(1) - systemd system and service manager
    systemd.automount(5) - Automount unit configuration
    systemd.device(5) - Device unit configuration
    systemd.directives(7) - Index of configuration directives
    systemd.environment-generator(7) - Systemd environment file generators
    systemd.exec(5) - Execution environment configuration
    systemd.generator(7) - Systemd unit generators
    systemd.index(7) - List all manpages from the systemd project
    systemd.journal-fields(7) - Special journal fields
    systemd.kill(5) - Process killing procedure configuration
    systemd.link(5) - Network device configuration
    systemd.mount(5) - Mount unit configuration
    systemd.negative(5) - DNSSEC trust anchor configuration files
    systemd.netdev(5) - Virtual Network Device configuration
    systemd.network(5) - Network configuration
    systemd.nspawn(5) - Container settings
    systemd.offline-updates(7) - Implementation of offline updates in systemd
    systemd.path(5) - Path unit configuration
    systemd.positive(5) - DNSSEC trust anchor configuration files
    systemd.preset(5) - Service enablement presets
    systemd.resource-control(5) - Resource control unit settings
    systemd.scope(5) - Scope unit configuration
    systemd.service(5) - Service unit configuration
    systemd.slice(5) - Slice unit configuration
    systemd.socket(5) - Socket unit configuration
    systemd.special(7) - Special systemd units
    systemd.swap(5) - Swap unit configuration
    systemd.target(5) - Target unit configuration
    systemd.time(7) - Time and date specifications
    systemd.timer(5) - Timer unit configuration
    systemd.unit(5) - Unit configuration
    systemkey-tool(1) - GnuTLS system key tool
    systemtap-service(8) - SystemTap initscript and systemd service
    systemtap(8) - SystemTap initscript service
    sys_time.h(0p) - time types
    sys_times.h(0p) - file access and modification times structure
    sys_types.h(0p) - data types
    sys_uio.h(0p) - definitions for vector I/O operations
    sys_un.h(0p) - definitions for UNIX domain sockets
    sysusers.d(5) - Declarative allocation of system users and groups
    sys_utsname.h(0p) - system name structure
    sysv_signal(3) - signal handling with System V semantics
    sys_wait.h(0p) - declarations for waiting

top
    TABS(1) - set tabs on a terminal
    tabs(1) - set tabs on a terminal
    tabs(1p) - set terminal tabs
    TABSIZE(3x) - curses global variables
    tac(1) - concatenate and print files in reverse
    tail(1) - output the last part of files
    tail(1p) - copy the last part of a file
    TAILQ_CONCAT(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_concat(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_EMPTY(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_empty(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_ENTRY(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_entry(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_FIRST(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_first(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_FOREACH(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_foreach(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_FOREACH_REVERSE(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_foreach_reverse(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_HEAD_INITIALIZER(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_head_initializer(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_INIT(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_init(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_INSERT_AFTER(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_insert_after(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_INSERT_BEFORE(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_insert_before(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_INSERT_HEAD(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_insert_head(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_INSERT_TAIL(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_insert_tail(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_LAST(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_last(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_NEXT(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_next(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_PREV(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_prev(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_REMOVE(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_remove(3) - linked lists, singly-linked tail queues, lists and tail queues
    TAILQ_SWAP(3) - linked lists, singly-linked tail queues, lists and tail queues
    tailq_swap(3) - linked lists, singly-linked tail queues, lists and tail queues
    talk(1p) - talk to another user
    tan(3) - tangent function
    tan(3p) - tangent function
    tanf(3) - tangent function
    tanf(3p) - tangent function
    tanh(3) - hyperbolic tangent function
    tanh(3p) - hyperbolic tangent functions
    tanhf(3) - hyperbolic tangent function
    tanhf(3p) - hyperbolic tangent functions
    tanhl(3) - hyperbolic tangent function
    tanhl(3p) - hyperbolic tangent functions
    tanl(3) - tangent function
    tanl(3p) - tangent function
    tapestat(1) - Report tape statistics.
    TAPRIO(8) - Time Aware Priority Shaper
    tar(1) - an archiving utility
    tar.h(0p) - extended tar definitions
    taskset(1) - set or retrieve a process's CPU affinity
    tbf(8) - Token Bucket Filter
    tbl(1) - format tables for troff
    tc-actions(8) - independently defined actions in tc
    tc-basic(8) - basic traffic control filter
    tc-bfifo(8) - Packet limited First In, First Out queue
    tc-bpf(8) - BPF programmable classifier and actions for ingress/egress queueing disciplines
    tc-cake(8) - Common Applications Kept Enhanced (CAKE)
    tc-cbq-details(8) - Class Based Queueing
    tc-cbq(8) - Class Based Queueing
    tc-cbs(8) - Credit Based Shaper (CBS) Qdisc
    tc-cgroup(8) - control group based traffic control filter
    tc-choke(8) - choose and keep scheduler
    tc-codel(8) - Controlled-Delay Active Queue Management algorithm
    tc-connmark(8) - netfilter connmark retriever action
    tc-csum(8) - checksum update action
    tc-drr(8) - deficit round robin scheduler
    tc-ematch(8) - extended matches for use with "basic" or "flow" filters
    tc-etf(8) - Earliest TxTime First (ETF) Qdisc
    tc-flow(8) - flow based traffic control filter
    tc-flower(8) - flow based traffic control filter
    tc-fq(8) - Fair Queue traffic policing
    tc-fq_codel(8) - Fair Queuing (FQ) with Controlled Delay (CoDel)
    tc-fw(8) - fwmark traffic control filter
    tc-hfcs(7) - Hierarchical Fair Service Curve
    tc-hfsc(7) - Hierarchical Fair Service Curve
    tc-hfsc(8) - Hierarchical Fair Service Curve's control under linux
    tc-htb(8) - Hierarchy Token Bucket
    tc-ife(8) - encapsulate/decapsulate metadata
    tc-matchall(8) - traffic control filter that matches every packet
    tc-mirred(8) - mirror/redirect action
    tc-mqprio(8) - Multiqueue Priority Qdisc (Offloaded Hardware QOS)
    tc-nat(8) - stateless native address translation action
    tc-netem(8) - Network Emulator
    tc-pedit(8) - generic packet editor action
    tc-pfifo(8) - Packet limited First In, First Out queue
    tc-pfifo_fast(8) - three-band first in, first out queue
    tc-pie(8) - Proportional Integral controller-Enhanced AQM algorithm
    tc-police(8) - policing action
    tc-prio(8) - Priority qdisc
    tc-red(8) - Random Early Detection
    tc-route(8) - route traffic control filter
    tc-sample(8) - packet sampling tc action
    tc-sfb(8) - Stochastic Fair Blue
    tc-sfq(8) - Stochastic Fairness Queueing
    tc-simple(8) - basic example action
    tc-skbedit(8) - SKB editing action
    tc-skbmod(8) - user-friendly packet editor action
    tc-skbprio(8) - SKB Priority Queue
    tc-stab(8) - Generic size table manipulations
    tc-taprio(8) - Time Aware Priority Shaper
    tc-tbf(8) - Token Bucket Filter
    tc-tcindex(8) - traffic control index filter
    tc-tunnel_key(8) - Tunnel metadata manipulation
    tc-u32(8) - universal 32bit traffic control filter
    tc-vlan(8) - vlan manipulation module
    tc-xt(8) - tc iptables action
    tc(8) - show / manipulate traffic control settings
    tcdrain(3) - get and set terminal attributes, line control, get and set baud rate
    tcdrain(3p) - wait for transmission of output
    tcflow(3) - get and set terminal attributes, line control, get and set baud rate
    tcflow(3p) - suspend or restart the transmission or reception of data
    tcflush(3) - get and set terminal attributes, line control, get and set baud rate
    tcflush(3p) - transmitted output data, non-read input data, or both
    tcgetattr(3) - get and set terminal attributes, line control, get and set baud rate
    tcgetattr(3p) - get the parameters associated with the terminal
    tcgetpgrp(3) - get and set terminal foreground process group
    tcgetpgrp(3p) - get the foreground process group ID
    tcgetsid(3) - get session ID
    tcgetsid(3p) - get the process group ID for the session leader for the controlling terminal
    tcindex(8) - traffic control index filter
    tcp(7) - TCP protocol
    tcpdump(1) - dump traffic on a network
    tcsendbreak(3) - get and set terminal attributes, line control, get and set baud rate
    tcsendbreak(3p) - send a break for a specific duration
    tcsetattr(3) - get and set terminal attributes, line control, get and set baud rate
    tcsetattr(3p) - set the parameters associated with the terminal
    tcsetpgrp(3) - get and set terminal foreground process group
    tcsetpgrp(3p) - set the foreground process group ID
    tdelete(3) - manage a binary search tree
    tdelete(3p) - manage a binary search tree
    tdestroy(3) - manage a binary search tree
    tee(1) - read from standard input and write to standard output and files
    tee(1p) - duplicate standard input
    tee(2) - duplicating pipe content
    telinit(8) - Change SysV runlevel
    telldir(3) - return current location in directory stream
    telldir(3p) - current location of a named directory stream
    telnet-probe(1) - lightweight telnet-like port probe
    tempnam(3) - create a name for a temporary file
    tempnam(3p) - create a name for a temporary file
    term(5) - format of compiled term file.
    term(7) - conventions for naming terminal types
    termattrs(3x) - curses environment query routines
    term_attrs(3x) - curses environment query routines
    termcap(5) - terminal capability database
    terminal-colors.d(5) - Configure output colorization for various utilities
    terminfo(5) - terminal capability data base
    termio(7) - System V terminal driver interface
    termios(3) - get and set terminal attributes, line control, get and set baud rate
    termios.h(0p) - define values for termios
    termname(3x) - curses environment query routines
    term_variables(3x) - curses terminfo global variables
    test(1) - check file types and compare values
    test(1p) - evaluate expression
    textdomain(3) - set domain for future gettext() calls
    tfind(3) - manage a binary search tree
    tfind(3p) - search binary search tree
    tfmtodit(1) - create font files for use with groff -Tdvi
    tftpd(8) - Trivial File Transfer Protocol server
    tgamma(3) - true gamma function
    tgamma(3p) - compute gamma() function
    tgammaf(3) - true gamma function
    tgammaf(3p) - compute gamma() function
    tgammal(3) - true gamma function
    tgammal(3p) - compute gamma() function
    tgetent(3x) - direct curses interface to the terminfo capability database
    tgetflag(3x) - direct curses interface to the terminfo capability database
    tgetnum(3x) - direct curses interface to the terminfo capability database
    tgetstr(3x) - direct curses interface to the terminfo capability database
    tgkill(2) - send a signal to a thread
    tgmath.h(0p) - generic macros
    tgoto(3x) - direct curses interface to the terminfo capability database
    thread-keyring(7) - per-thread keyring
    tigetflag(3x) - curses interfaces to terminfo database
    tigetnum(3x) - curses interfaces to terminfo database
    tigetstr(3x) - curses interfaces to terminfo database
    time(1) - time a simple command or give resource usage
    time(1p) - time a simple command
    time(2) - get time in seconds
    time(3p) - get time
    time(7) - overview of time and timers
    time.conf(5) - configuration file for the pam_time module
    time.h(0p) - time types
    timedatectl(1) - Control the system time and date
    timegm(3) - inverses of gmtime and localtime
    timelocal(3) - inverses of gmtime and localtime
    timeout(1) - run a command with a time limit
    timeout(3x) - curses input options
    timeradd(3) - timeval operations
    timerclear(3) - timeval operations
    timercmp(3) - timeval operations
    timer_create(2) - create a POSIX per-process timer
    timer_create(3p) - process timer
    timer_delete(2) - delete a POSIX per-process timer
    timer_delete(3p) - process timer
    timerfd_create(2) - timers that notify via file descriptors
    timerfd_gettime(2) - timers that notify via file descriptors
    timerfd_settime(2) - timers that notify via file descriptors
    timer_getoverrun(2) - get overrun count for a POSIX per-process timer
    timer_getoverrun(3p) - process timers
    timer_gettime(2) - arm/disarm and fetch state of POSIX per-process timer
    timer_gettime(3p) - process timers
    timerisset(3) - timeval operations
    timer_settime(2) - arm/disarm and fetch state of POSIX per-process timer
    timer_settime(3p) - process timers
    timersub(3) - timeval operations
    times(1p) - write process times
    times(2) - get process times
    times(3p) - for child process times
    timesyncd.conf(5) - Network Time Synchronization configuration files
    timesyncd.conf.d(5) - Network Time Synchronization configuration files
    timezone(3) - initialize time conversion information
    timezone(3p) - difference from UTC and local standard time
    tiparm(3x) - curses interfaces to terminfo database
    tipc-bearer(8) - show or modify TIPC bearers
    tipc-link(8) - show links or modify link properties
    tipc-media(8) - list or modify media properties
    tipc-nametable(8) - show TIPC nametable
    tipc-node(8) - modify and show local node parameters or list peer nodes
    tipc-peer(8) - modify peer information
    tipc-socket(8) - show TIPC socket (port) information
    tipc(8) - a TIPC configuration and management tool
    tis-620(7) - ISO 8859-11 character set encoded in octal, decimal, and hexadecimal
    tkill(2) - send a signal to a thread
    tload(1) - graphic representation of system load average
    tmpfile(3) - create a temporary file
    tmpfile(3p) - create a temporary file
    tmpfiles.d(5) - Configuration for creation, deletion and cleaning of volatile and temporary files
    tmpfs(5) - a virtual memory filesystem
    tmpnam(3) - create a name for a temporary file
    tmpnam(3p) - create a name for a temporary file
    tmpnam_r(3) - create a name for a temporary file
    tmux(1) - terminal multiplexer
    toascii(3) - convert character to ASCII
    toascii(3p) - bit ASCII character
    togglesebool(8) - flip the current value of a SELinux boolean
    tokuftdump(1) - look into the fractal tree file
    tokuft_logprint(1) - Dump the log from stdin to stdout
    tolower(3) - convert uppercase or lowercase
    tolower(3p) - transliterate uppercase characters to lowercase
    _tolower(3p) - transliterate uppercase characters to lowercase
    tolower_l(3) - convert uppercase or lowercase
    tolower_l(3p) - transliterate uppercase characters to lowercase
    top(1) - display Linux processes
    touch(1) - change file timestamps
    touch(1p) - change file access and modification times
    touchline(3x) - curses refresh control routines
    touchwin(3x) - curses refresh control routines
    toupper(3) - convert uppercase or lowercase
    toupper(3p) - transliterate lowercase characters to uppercase
    _toupper(3p) - transliterate lowercase characters to uppercase
    toupper_l(3) - convert uppercase or lowercase
    toupper_l(3p) - transliterate lowercase characters to uppercase
    towctrans(3) - wide-character transliteration
    towctrans(3p) - character transliteration
    towctrans_l(3p) - character transliteration
    towlower(3) - convert a wide character to lowercase
    towlower(3p) - character code to lowercase
    towlower_l(3) - convert a wide character to lowercase
    towlower_l(3p) - character code to lowercase
    towupper(3) - convert a wide character to uppercase
    towupper(3p) - character code to uppercase
    towupper_l(3) - convert a wide character to uppercase
    towupper_l(3p) - character code to uppercase
    tparm(3x) - curses interfaces to terminfo database
    tpmtool(1) - GnuTLS TPM tool
    TPUT(1) - initialize a terminal or query terminfo database
    tput(1) - initialize a terminal or query terminfo database
    tput(1p) - change terminal characteristics
    tputs(3x) - direct curses interface to the terminfo capability database
    tr(1) - translate or delete characters
    tr(1p) - translate characters
    trace-cmd-check-events(1) - parse the event formats on local system
    trace-cmd-extract(1) - extract out the data from the Ftrace Linux tracer.
    trace-cmd-hist(1) - show histogram of events in trace.dat file
    trace-cmd-list(1) - list available plugins, events or options for Ftrace.
    trace-cmd-listen(1) - listen for incoming connection to record tracing.
    trace-cmd-mem(1) - show memory usage of certain kmem events
    trace-cmd-options(1) - list available options from trace-cmd plugins
    trace-cmd-profile(1) - profile tasks running live
    trace-cmd-record(1) - record a trace from the Ftrace Linux internal tracer
    trace-cmd-report(1) - show in ASCII a trace created by trace-cmd record
    trace-cmd-reset(1) - turn off all Ftrace tracing to bring back full performance
    trace-cmd-restore(1) - restore a failed trace record
    trace-cmd-show(1) - show the contents of the Ftrace Linux kernel tracing buffer.
    trace-cmd-snapshot(1) - take, reset, free, or show a Ftrace kernel snapshot
    trace-cmd-split(1) - split a trace.dat file into smaller files
    trace-cmd-stack(1) - read, enable or disable Ftrace Linux kernel stack tracing.
    trace-cmd-start(1) - start the Ftrace Linux kernel tracer without recording
    trace-cmd-stat(1) - show the status of the tracing (ftrace) system
    trace-cmd-stop(1) - stop the Ftrace Linux kernel tracer from writing to the ring buffer.
    trace-cmd-stream(1) - stream a trace to stdout as it is happening
    trace-cmd(1) - interacts with Ftrace Linux kernel internal tracer
    trace-cmd.dat(5) - trace-cmd file format
    trace(3x) - curses debugging routines
    trace.h(0p) - tracing
    _traceattr(3x) - curses debugging routines
    _traceattr2(3x) - curses debugging routines
    _tracecchar_t(3x) - curses debugging routines
    _tracecchar_t2(3x) - curses debugging routines
    _tracechar(3x) - curses debugging routines
    _tracechtype(3x) - curses debugging routines
    _tracechtype2(3x) - curses debugging routines
    _tracedump(3x) - curses debugging routines
    tracef(3) - LTTng-UST printf(3)-like interface
    _tracef(3x) - curses debugging routines
    tracelog(3) - LTTng-UST printf(3)-like interface with a log level
    _tracemouse(3x) - curses debugging routines
    tracepath(8) - traces path to a network host discovering MTU along this path
    tracepath6(8) - traces path to a network host discovering MTU along this path
    tracepoint(3) - LTTng user space tracing
    tracepoint_enabled(3) - LTTng user space tracing
    traceroute(8) - print the route packets trace to network host
    traceroute6(8) - traces path to a network host
    trafgen(8) - a fast, multithreaded network packet generator
    trap(1p) - trap signals
    troff(1) - the troff processor of the groff text formatting system
    true(1) - do nothing, successfully
    true(1p) - return true value
    trunc(3) - round to integer, toward zero
    trunc(3p) - round to truncated integer value
    truncate(1) - shrink or extend the size of a file to the specified size
    truncate(2) - truncate a file to a specified length
    truncate(3p) - truncate a file to a specified length
    truncate64(2) - truncate a file to a specified length
    truncf(3) - round to integer, toward zero
    truncf(3p) - round to truncated integer value
    truncl(3) - round to integer, toward zero
    truncl(3p) - round to truncated integer value
    tsearch(3) - manage a binary search tree
    tsearch(3p) - search a binary search tree
    TSET(1) - terminal initialization
    tset(1) - terminal initialization
    tsort(1) - perform topological sort
    tsort(1p) - topological sort
    tty(1) - print the file name of the terminal connected to standard input
    tty(1p) - return user's terminal name
    tty(4) - controlling terminal
    tty_ioctl(4) - ioctls for terminals and serial lines
    ttyname(3) - return name of a terminal
    ttyname(3p) - find the pathname of a terminal
    ttyname_r(3) - return name of a terminal
    ttyname_r(3p) - find the pathname of a terminal
    ttyS(4) - serial terminal lines
    ttys(4) - serial terminal lines
    ttyslot(3) - find the slot of the current user's terminal in some file
    ttytype(3x) - curses terminfo global variables
    ttytype(5) - terminal device to default terminal type mapping
    tune2fs(8) - adjust tunable filesystem parameters on ext2/ext3/ext4 filesystems
    tunelp(8) - set various parameters for the lp device
    tunnel_key(8) - Tunnel metadata manipulation
    tuxcall(2) - unimplemented system calls
    twalk(3) - manage a binary search tree
    twalk(3p) - traverse a binary search tree
    type(1p) - write a description of command type
    typeahead(3x) - curses input options
    TYPE_ALNUM(3x) - form system global variables
    TYPE_ALPHA(3x) - form system global variables
    TYPE_ENUM(3x) - form system global variables
    TYPE_INTEGER(3x) - form system global variables
    TYPE_IPV4(3x) - form system global variables
    TYPE_NUMERIC(3x) - form system global variables
    TYPE_REGEXP(3x) - form system global variables
    tzfile(5) - timezone information
    tzname(3) - initialize time conversion information
    tzname(3p) - set timezone conversion information
    tzselect(8) - select a timezone
    tzset(3) - initialize time conversion information
    tzset(3p) - set timezone conversion information

top
    u32(8) - universal 32bit traffic control filter
    ualarm(3) - schedule signal after given number of microseconds
    ucmatose(1) - RDMA CM connection and simple ping-pong test.
    udaddy(1) - RDMA CM datagram setup and simple ping-pong test.
    udev(7) - Dynamic device management
    udev.conf(5) - Configuration for device event managing daemon
    udevadm(8) - udev management tool
    udev_device_get_action(3) - Query device properties
    udev_device_get_devlinks_list_entry(3) - Retrieve or set device attributes
    udev_device_get_devnode(3) - Query device properties
    udev_device_get_devnum(3) - Query device properties
    udev_device_get_devpath(3) - Query device properties
    udev_device_get_devtype(3) - Query device properties
    udev_device_get_driver(3) - Query device properties
    udev_device_get_is_initialized(3) - Query device properties
    udev_device_get_parent(3) - Query device properties
    udev_device_get_parent_with_subsystem_devtype(3) - Query device properties
    udev_device_get_properties_list_entry(3) - Retrieve or set device attributes
    udev_device_get_property_value(3) - Retrieve or set device attributes
    udev_device_get_subsystem(3) - Query device properties
    udev_device_get_sysattr_list_entry(3) - Retrieve or set device attributes
    udev_device_get_sysattr_value(3) - Retrieve or set device attributes
    udev_device_get_sysname(3) - Query device properties
    udev_device_get_sysnum(3) - Query device properties
    udev_device_get_syspath(3) - Query device properties
    udev_device_get_tags_list_entry(3) - Retrieve or set device attributes
    udev_device_get_udev(3) - Query device properties
    udev_device_has_tag(3) - Retrieve or set device attributes
    udev_device_new_from_device_id(3) - Create, acquire and release a udev device object
    udev_device_new_from_devnum(3) - Create, acquire and release a udev device object
    udev_device_new_from_environment(3) - Create, acquire and release a udev device object
    udev_device_new_from_subsystem_sysname(3) - Create, acquire and release a udev device object
    udev_device_new_from_syspath(3) - Create, acquire and release a udev device object
    udev_device_ref(3) - Create, acquire and release a udev device object
    udev_device_set_sysattr_value(3) - Retrieve or set device attributes
    udev_device_unref(3) - Create, acquire and release a udev device object
    udev_enumerate_add_match_is_initialized(3) - Modify filters
    udev_enumerate_add_match_parent(3) - Modify filters
    udev_enumerate_add_match_property(3) - Modify filters
    udev_enumerate_add_match_subsystem(3) - Modify filters
    udev_enumerate_add_match_sysattr(3) - Modify filters
    udev_enumerate_add_match_sysname(3) - Modify filters
    udev_enumerate_add_match_tag(3) - Modify filters
    udev_enumerate_add_nomatch_subsystem(3) - Modify filters
    udev_enumerate_add_nomatch_sysattr(3) - Modify filters
    udev_enumerate_add_syspath(3) - Query or modify a udev enumerate object
    udev_enumerate_get_list_entry(3) - Query or modify a udev enumerate object
    udev_enumerate_get_udev(3) - Query or modify a udev enumerate object
    udev_enumerate_new(3) - Create, acquire and release a udev enumerate object
    udev_enumerate_ref(3) - Create, acquire and release a udev enumerate object
    udev_enumerate_scan_devices(3) - Query or modify a udev enumerate object
    udev_enumerate_scan_subsystems(3) - Query or modify a udev enumerate object
    udev_enumerate_unref(3) - Create, acquire and release a udev enumerate object
    udev_list_entry(3) - Iterate and access udev lists
    udev_list_entry_get_by_name(3) - Iterate and access udev lists
    udev_list_entry_get_name(3) - Iterate and access udev lists
    udev_list_entry_get_next(3) - Iterate and access udev lists
    udev_list_entry_get_value(3) - Iterate and access udev lists
    udev_monitor_enable_receiving(3) - Query and modify device monitor
    udev_monitor_filter_add_match_subsystem_devtype(3) - Modify filters
    udev_monitor_filter_add_match_tag(3) - Modify filters
    udev_monitor_filter_remove(3) - Modify filters
    udev_monitor_filter_update(3) - Modify filters
    udev_monitor_get_fd(3) - Query and modify device monitor
    udev_monitor_get_udev(3) - Query and modify device monitor
    udev_monitor_new_from_netlink(3) - Create, acquire and release a udev monitor object
    udev_monitor_receive_device(3) - Query and modify device monitor
    udev_monitor_ref(3) - Create, acquire and release a udev monitor object
    udev_monitor_set_receive_buffer_size(3) - Query and modify device monitor
    udev_monitor_unref(3) - Create, acquire and release a udev monitor object
    udev_new(3) - Create, acquire and release a udev context object
    udev_ref(3) - Create, acquire and release a udev context object
    udev_unref(3) - Create, acquire and release a udev context object
    udp(7) - User Datagram Protocol for IPv4
    udplite(7) - Lightweight User Datagram Protocol
    udpong(1) - unreliable datagram streaming over RDMA ping-pong test.
    ugetrlimit(2) - get/set resource limits
    ul(1) - do underlining
    ulckpwdf(3) - get shadow password file entry
    ulimit(1p) - set or report file size limit
    ulimit(3) - get and set user limits
    ulimit(3p) - get and set process limits
    ulimit.h(0p) - ulimit commands
    umad_addr_dump(3) - dump addr structure to stderr
    umad_alloc(3) - allocate memory for umad buffers
    umad_class_str(3) - class of functions to return string representations of enums
    umad_close_port(3) - close InfiniBand device port for umad access
    umad_debug(3) - set debug level
    umad_dump(3) - dump umad buffer to stderr
    umad_free(3) - frees memory of umad buffers
    umad_get_ca(3) - get and release InfiniBand device port attributes
    umad_get_ca_portguids(3) - get the InfiniBand device ports GUIDs
    umad_get_cas_names(3) - get list of available InfiniBand device names
    umad_get_fd(3) - get the umad fd for the requested port
    umad_get_issm_path(3) - get path of issm device
    umad_get_mad(3) - get the MAD pointer of a umad buffer
    umad_get_mad_addr(3) - get the address of the ib_mad_addr from a umad buffer
    umad_get_pkey(3) - get pkey index from umad buffer
    umad_get_port(3) - open and close an InfiniBand port
    umad_open_port(3) - open InfiniBand device port for umad access
    umad_poll(3) - poll umad
    umad_recv(3) - receive umad
    umad_register(3) - register the specified management class and version for port
    umad_register2(3) - register the specified management class and version for port
    umad_register_oui(3) - register the specified class in vendor range 2 for port
    umad_release_ca(3) - get and release InfiniBand device port attributes
    umad_release_port(3) - open and close an InfiniBand port
    umad_send(3) - send umad
    umad_set_addr(3) - set MAD address fields within umad buffer using host ordering
    umad_set_addr_net(3) - set MAD address fields within umad buffer using network ordering
    umad_set_grh(3) - set GRH fields within umad buffer using host ordering
    umad_set_grh_net(3) - set GRH fields within umad buffer using network ordering
    umad_set_pkey(3) - set pkey index within umad buffer
    umad_size(3) - get the size of umad buffer
    umad_status(3) - get the status of a umad buffer
    umad_unregister(3) - unregister umad agent
    umask(1p) - get or set the file mode creation mask
    umask(2) - set file mode creation mask
    umask(3p) - set and get the file mode creation mask
    umount(2) - unmount filesystem
    umount(8) - unmount file systems
    umount.nfs(8) - unmount a Network File System
    umount.nfs4(8) - unmount a Network File System
    umount2(2) - unmount filesystem
    unalias(1p) - remove alias definitions
    uname(1) - print system information
    uname(1p) - return system name
    uname(2) - get name and information about current kernel
    uname(3p) - get the name of the current system
    uname26(8) - change reported architecture in new program environment and/or set personality flags
    uncompress(1p) - expand compressed data
    unctrl(3x) - miscellaneous curses utility routines
    undocumented(3) - undocumented library functions
    unexpand(1) - convert spaces to tabs
    unexpand(1p) - convert spaces to tabs
    unget(1p) - undo a previous get of an SCCS file (DEVELOPMENT)
    ungetc(3) - input of characters and strings
    ungetc(3p) - push byte back into input stream
    ungetch(3x) - get (or push back) characters from curses terminal keyboard
    ungetmouse(3x) - mouse interface through curses
    ungetwc(3) - push back a wide character onto a FILE stream
    ungetwc(3p) - character code back into the input stream
    unget_wch(3x) - get (or push back) a wide character from curses terminal keyboard
    unicode(7) - universal character set
    unicode_start(1) - put keyboard and console in unicode mode
    unicode_stop(1) - revert keyboard and console from unicode mode
    unimplemented(2) - unimplemented system calls
    uniq(1) - report or omit repeated lines
    uniq(1p) - report or filter out repeated lines in a file
    unistd.h(0p) - standard symbolic constants and types
    units(7) - decimal and binary prefixes
    unix(7) - sockets for local interprocess communication
    unix_chkpwd(8) - Helper binary that verifies the password of the current user
    unix_update(8) - Helper binary that updates the password of a given user
    unlink(1) - call the unlink function to remove the specified file
    unlink(1p) - call the unlink() function
    unlink(2) - delete a name and possibly the file it refers to
    unlink(3p) - remove a directory entry relative to directory file descriptor
    unlinkat(2) - delete a name and possibly the file it refers to
    unlinkat(3p) - remove a directory entry relative to directory file descriptor
    unlocked_stdio(3) - nonlocking stdio functions
    unlockpt(3) - unlock a pseudoterminal master/slave pair
    unlockpt(3p) - terminal master/slave pair
    unpost_form(3x) - write or erase forms from associated subwindows
    unpost_menu(3x) - write or erase menus from associated subwindows
    unset(1p) - unset values and attributes of variables and functions
    unsetenv(3) - change or add an environment variable
    unsetenv(3p) - remove an environment variable
    unshare(1) - run program with some namespaces unshared from parent
    unshare(2) - disassociate parts of the process execution context
    untouchwin(3x) - curses refresh control routines
    UP(3x) - direct curses interface to the terminfo capability database
    update-alternatives(1) - maintain symbolic links determining default commands
    update-pciids(8) - download new version of the PCI ID list
    updatedb(1) - update a file name database
    updwtmp(3) - append an entry to the wtmp file
    updwtmpx(3) - append an entry to the wtmp file
    uptime(1) - Tell how long the system has been running.
    urandom(4) - kernel random number source devices
    uri(7) - uniform resource identifier (URI), including a URL or URN
    url(7) - uniform resource identifier (URI), including a URL or URN
    urn(7) - uniform resource identifier (URI), including a URL or URN
    usb-devices(1) - print USB device details
    use_default_colors(3x) - use terminal's default colors
    use_env(3x) - miscellaneous curses utility routines
    use_extended_names(3x) - miscellaneous curses extensions
    use_legacy_coding(3x) - override locale-encoding checks
    uselib(2) - load shared library
    uselocale(3) - set/get the locale for the calling thread
    uselocale(3p) - use locale in current thread
    user-keyring(7) - per-user keyring
    user-session-keyring(7) - per-user default session keyring
    user.conf.d(5) - System and session service manager configuration files
    useradd(8) - create a new user or update default new user information
    user_caps(5) - user-defined terminfo capabilities
    user_contexts(5) - The SELinux user contexts configuration files
    userdel(8) - delete a user account and related files
    userfaultfd(2) - create a file descriptor for handling page faults in user space
    usermod(8) - modify a user account
    user_namespaces(7) - overview of Linux user namespaces
    users(1) - print the user names of users currently logged in to the current host
    use_tioctl(3x) - miscellaneous curses utility routines
    usleep(3) - suspend execution for microsecond intervals
    ustat(2) - get filesystem statistics
    UTF-8(7) - an ASCII compatible multibyte Unicode encoding
    utf-8(7) - an ASCII compatible multibyte Unicode encoding
    utf8(7) - an ASCII compatible multibyte Unicode encoding
    utime(2) - change file last access and modification times
    utime(3p) - set file access and modification times
    utime.h(0p) - access and modification times structure
    utimensat(2) - change file timestamps with nanosecond precision
    utimensat(3p) - set file access and modification times relative to directory file descriptor
    utimes(2) - change file last access and modification times
    utimes(3p) - set file access and modification times
    utmp(5) - login records
    utmpdump(1) - dump UTMP and WTMP files in raw format
    utmpname(3) - access utmp file entries
    utmpx(5) - login records
    utmpx.h(0p) - user accounting database definitions
    utmpxname(3) - access utmp file entries
    uucp(1p) - to-system copy
    uudecode(1p) - decode a binary file
    uuencode(1p) - encode a binary file
    uuid(3) - DCE compatible Universally Unique Identifier library
    uuid_clear(3) - reset value of UUID variable to the NULL value
    uuid_compare(3) - compare whether two UUIDs are the same
    uuid_copy(3) - copy a UUID value
    uuidd(8) - UUID generation daemon
    uuidgen(1) - create a new UUID value
    uuid_generate(3) - create a new unique UUID value
    uuid_generate_random(3) - create a new unique UUID value
    uuid_generate_time(3) - create a new unique UUID value
    uuid_generate_time_safe(3) - create a new unique UUID value
    uuid_is_null(3) - compare the value of the UUID to the NULL value
    uuidparse(1) - a utility to parse unique identifiers
    uuid_parse(3) - convert an input UUID string into binary representation
    uuid_time(3) - extract the time at which the UUID was created
    uuid_unparse(3) - convert a UUID from binary representation to a string
    uustat(1p) - uucp status enquiry and job control
    uux(1p) - remote command execution

top
    va_arg(3) - variable argument lists
    va_arg(3p) - handle variable argument list
    va_copy(3) - variable argument lists
    va_copy(3p) - handle variable argument list
    va_end(3) - variable argument lists
    va_end(3p) - handle variable argument list
    val(1p) - validate SCCS files (DEVELOPMENT)
    valgrind-listener(1) - listens on a socket for Valgrind commentary
    valgrind(1) - a suite of tools for debugging and profiling programs
    valloc(3) - allocate aligned memory
    vasprintf(3) - print to allocated string
    va_start(3) - variable argument lists
    va_start(3p) - handle variable argument list
    vconsole.conf(5) - Configuration file for the virtual console
    vcs(4) - virtual console memory
    vcsa(4) - virtual console memory
    vdir(1) - list directory contents
    vdprintf(3) - formatted output conversion
    vdprintf(3p) - format output of a stdarg argument list
    vdso(7) - overview of the virtual ELF dynamic shared object
    verify_blkparse(1) - verifies an output file produced by blkparse
    verifytree(1) - verify that a local yum repository is consistent
    veritysetup(8) - manage dm-verity (block level verification) volumes
    verr(3) - formatted error messages
    verrx(3) - formatted error messages
    versionsort(3) - scan a directory for matching entries
    veth(4) - Virtual Ethernet Device
    vfork(2) - create a child process and block parent
    vfprintf(3) - formatted output conversion
    vfprintf(3p) - format output of a stdarg argument list
    vfscanf(3) - input format conversion
    vfscanf(3p) - format input of a stdarg argument list
    vfwprintf(3) - formatted wide-character output conversion
    vfwprintf(3p) - character formatted output of a stdarg argument list
    vfwscanf(3p) - character formatted input of a stdarg argument list
    vgcfgbackup(8) - Backup volume group configuration(s)
    vgcfgrestore(8) - Restore volume group configuration
    vgchange(8) - Change volume group attributes
    vgck(8) - Check the consistency of volume group(s)
    vgconvert(8) - Change volume group metadata format
    vgcreate(8) - Create a volume group
    vgdb(1) - intermediary between Valgrind and GDB or a shell
    vgdisplay(8) - Display volume group information
    vgexport(8) - Unregister volume group(s) from the system
    vgextend(8) - Add physical volumes to a volume group
    vgimport(8) - Register exported volume group with system
    vgimportclone(8) - Import a VG from cloned PVs
    vgmerge(8) - Merge volume groups
    vgmknodes(8) - Create the special files for volume group devices in /dev
    vgreduce(8) - Remove physical volume(s) from a volume group
    vgremove(8) - Remove volume group(s)
    vgrename(8) - Rename a volume group
    vgs(8) - Display information about volume groups
    vgscan(8) - Search for all volume groups
    vgsplit(8) - Move physical volumes into a new or existing volume group
    vhangup(2) - virtually hangup the current terminal
    vi(1p) - oriented (visual) display editor
    vidattr(3x) - curses interfaces to terminfo database
    vid_attr(3x) - curses interfaces to terminfo database
    vidputs(3x) - curses interfaces to terminfo database
    vid_puts(3x) - curses interfaces to terminfo database
    vigr(8) - edit the password, group, shadow-password or shadow-group file
    vipw(8) - edit the password, group, shadow-password or shadow-group file
    virtual_domain_context(5) - The SELinux virtual machine domain context configuration file
    virtual_image_context(5) - The SELinux virtual machine image context configuration file
    vlan(8) - vlan manipulation module
    vlimit(3) - get/set resource limits
    vline(3x) - create curses borders, horizontal and vertical lines
    vline_set(3x) - create curses borders or lines using complex characters and renditions
    vlock(1) - Virtual Console lock program
    vm86(2) - enter virtual 8086 mode
    vm86old(2) - enter virtual 8086 mode
    vmsplice(2) - splice user pages into a pipe
    vmstat(8) - Report virtual memory statistics
    vprintf(3) - formatted output conversion
    vprintf(3p) - format the output of a stdarg argument list
    vscanf(3) - input format conversion
    vscanf(3p) - format input of a stdarg argument list
    vserver(2) - unimplemented system calls
    vsnprintf(3) - formatted output conversion
    vsnprintf(3p) - format output of a stdarg argument list
    vsock(7) - Linux VSOCK address family
    vsprintf(3) - formatted output conversion
    vsprintf(3p) - format output of a stdarg argument list
    vsscanf(3) - input format conversion
    vsscanf(3p) - format input of a stdarg argument list
    vswprintf(3) - formatted wide-character output conversion
    vswprintf(3p) - character formatted output of a stdarg argument list
    vswscanf(3p) - character formatted input of a stdarg argument list
    vsyslog(3) - send messages to the system logger
    vtep-ctl(8) - utility for querying and configuring a VTEP database
    vtep(5) - hardware_vtep database schema
    vtimes(3) - get resource usage
    vwarn(3) - formatted error messages
    vwarnx(3) - formatted error messages
    vwprintf(3) - formatted wide-character output conversion
    vwprintf(3p) - character formatted output of a stdarg argument list
    vwprintw(3x) - print formatted output in curses windows
    vw_printw(3x) - print formatted output in curses windows
    vwscanf(3p) - character formatted input of a stdarg argument list
    vwscanw(3x) - convert formatted input from a curses window
    vw_scanw(3x) - convert formatted input from a curses window

top
    w(1) - Show who is logged on and what they are doing.
    waddch(3x) - add a character (with attributes) to a curses window, then advance the cursor
    waddchnstr(3x) - add a string of characters (and attributes) to a curses window
    waddchstr(3x) - add a string of characters (and attributes) to a curses window
    waddnstr(3x) - add a string of characters to a curses window and advance cursor
    waddnwstr(3x) - add a string of wide characters to a curses window and advance cursor
    waddstr(3x) - add a string of characters to a curses window and advance cursor
    wadd_wch(3x) - add a complex character and rendition to a curses window, then advance the cursor
    wadd_wchnstr(3x) - add an array of complex characters (and attributes) to a curses window
    wadd_wchstr(3x) - add an array of complex characters (and attributes) to a curses window
    waddwstr(3x) - add a string of wide characters to a curses window and advance cursor
    wait(1p) - await process completion
    wait(2) - wait for process to change state
    wait(3p) - wait for a child process to stop or terminate
    wait3(2) - wait for process to change state, BSD style
    wait4(2) - wait for process to change state, BSD style
    waitid(2) - wait for process to change state
    waitid(3p) - wait for a child process to change state
    waitpid(2) - wait for process to change state
    waitpid(3p) - wait for a child process to stop or terminate
    wall(1) - write a message to all users
    warn(3) - formatted error messages
    warning::debuginfo(7stap) - systemtap missing-debuginfo warnings
    warning::process-tracking(7stap) - process-tracking facilities are not available
    warning::symbols(7stap) - systemtap missing-symbols warnings
    warnquota(8) - send mail to users over quota
    warnquota.conf(5) - configuration for warnquota
    warnx(3) - formatted error messages
    watch(1) - execute a program periodically, showing output fullscreen
    wattr_get(3x) - curses character and window attribute control routines
    wattroff(3x) - curses character and window attribute control routines
    wattr_off(3x) - curses character and window attribute control routines
    wattron(3x) - curses character and window attribute control routines
    wattr_on(3x) - curses character and window attribute control routines
    wattrset(3x) - curses character and window attribute control routines
    wattr_set(3x) - curses character and window attribute control routines
    wavelan(4) - AT&T GIS WaveLAN ISA device driver
    wbkgd(3x) - curses window background manipulation routines
    wbkgdset(3x) - curses window background manipulation routines
    wbkgrnd(3x) - curses window complex background manipulation routines
    wbkgrndset(3x) - curses window complex background manipulation routines
    wborder(3x) - create curses borders, horizontal and vertical lines
    wborder_set(3x) - create curses borders or lines using complex characters and renditions
    wc(1) - print newline, word, and byte counts for each file
    wc(1p) - word, line, and byte or character count
    wchar.h(0p) - character handling
    wchgat(3x) - curses character and window attribute control routines
    wclear(3x) - clear all or part of a curses window
    wclrtobot(3x) - clear all or part of a curses window
    wclrtoeol(3x) - clear all or part of a curses window
    wcolor_set(3x) - curses character and window attribute control routines
    wcpcpy(3) - copy a wide-character string, returning a pointer to its end
    wcpcpy(3p) - character string, returning a pointer to its end
    wcpncpy(3) - copy a fixed-size string of wide characters, returning a pointer to its end
    wcpncpy(3p) - size wide-character string, returning a pointer to its end
    wcrtomb(3) - convert a wide character to a multibyte sequence
    wcrtomb(3p) - character code to a character (restartable)
    wcscasecmp(3) - compare two wide-character strings, ignoring case
    wcscasecmp(3p) - insensitive wide-character string comparison
    wcscasecmp_l(3p) - insensitive wide-character string comparison
    wcscat(3) - concatenate two wide-character strings
    wcscat(3p) - character strings
    wcschr(3) - search a wide character in a wide-character string
    wcschr(3p) - character string scanning operation
    wcscmp(3) - compare two wide-character strings
    wcscmp(3p) - character strings
    wcscoll(3p) - character string comparison using collating information
    wcscoll_l(3p) - character string comparison using collating information
    wcscpy(3) - copy a wide-character string
    wcscpy(3p) - character string, returning a pointer to its end
    wcscspn(3) - search a wide-character string for any of a set of wide characters
    wcscspn(3p) - get the length of a complementary wide substring
    wcsdup(3) - duplicate a wide-character string
    wcsdup(3p) - character string
    wcsftime(3p) - character string
    wcslen(3) - determine the length of a wide-character string
    wcslen(3p) - sized wide-character string
    wcsncasecmp(3) - compare two fixed-size wide-character strings, ignoring case
    wcsncasecmp(3p) - insensitive wide-character string comparison
    wcsncasecmp_l(3p) - insensitive wide-character string comparison
    wcsncat(3) - concatenate two wide-character strings
    wcsncat(3p) - character string with part of another
    wcsncmp(3) - compare two fixed-size wide-character strings
    wcsncmp(3p) - character strings
    wcsncpy(3) - copy a fixed-size string of wide characters
    wcsncpy(3p) - size wide-character string, returning a pointer to its end
    wcsnlen(3) - determine the length of a fixed-size wide-character string
    wcsnlen(3p) - sized wide-character string
    wcsnrtombs(3) - convert a wide-character string to a multibyte string
    wcsnrtombs(3p) - character string to multi-byte string
    wcspbrk(3) - search a wide-character string for any of a set of wide characters
    wcspbrk(3p) - character string for a wide-character code
    wcsrchr(3) - search a wide character in a wide-character string
    wcsrchr(3p) - character string scanning operation
    wcsrtombs(3) - convert a wide-character string to a multibyte string
    wcsrtombs(3p) - character string to a character string (restartable)
    wcsspn(3) - advance in a wide-character string, skipping any of a set of wide characters
    wcsspn(3p) - get the length of a wide substring
    wcsstr(3) - locate a substring in a wide-character string
    wcsstr(3p) - character substring
    wcstod(3p) - character string to a double-precision number
    wcstof(3p) - character string to a double-precision number
    wcstoimax(3) - convert wide-character string to integer
    wcstoimax(3p) - character string to an integer type
    wcstok(3) - split wide-character string into tokens
    wcstok(3p) - character string into tokens
    wcstol(3p) - character string to a long integer
    wcstold(3p) - character string to a double-precision number
    wcstoll(3p) - character string to a long integer
    wcstombs(3) - convert a wide-character string to a multibyte string
    wcstombs(3p) - character string to a character string
    wcstoul(3p) - character string to an unsigned long
    wcstoull(3p) - character string to an unsigned long
    wcstoumax(3) - convert wide-character string to integer
    wcstoumax(3p) - character string to an integer type
    wcswidth(3) - determine columns needed for a fixed-size wide-character string
    wcswidth(3p) - character string
    wcsxfrm(3p) - character string transformation
    wcsxfrm_l(3p) - character string transformation
    wctob(3) - try to represent a wide character as a single byte
    wctob(3p) - character to single-byte conversion
    wctomb(3) - convert a wide character to a multibyte sequence
    wctomb(3p) - character code to a character
    wctrans(3) - wide-character translation mapping
    wctrans(3p) - define character mapping
    wctrans_l(3p) - define character mapping
    wctype(3) - wide-character classification
    wctype(3p) - define character class
    wctype.h(0p) - character classification and mapping utilities
    wctype_l(3p) - define character class
    wcursyncup(3x) - create curses windows
    wcwidth(3) - determine columns needed for a wide character
    wcwidth(3p) - character code
    wdctl(8) - show hardware watchdog status
    wdelch(3x) - delete character under the cursor in a curses window
    wdeleteln(3x) - delete and insert lines in a curses window
    wechochar(3x) - add a character (with attributes) to a curses window, then advance the cursor
    wecho_wchar(3x) - add a complex character and rendition to a curses window, then advance the cursor
    wenclose(3x) - mouse interface through curses
    werase(3x) - clear all or part of a curses window
    Wget(1) - The non-interactive network downloader.
    wget(1) - The non-interactive network downloader.
    wgetbkgrnd(3x) - curses window complex background manipulation routines
    wgetch(3x) - get (or push back) characters from curses terminal keyboard
    wgetdelay(3x) - curses window properties
    wgetnstr(3x) - accept character strings from curses terminal keyboard
    wgetn_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    wgetparent(3x) - curses window properties
    wgetscrreg(3x) - curses window properties
    wgetstr(3x) - accept character strings from curses terminal keyboard
    wget_wch(3x) - get (or push back) a wide character from curses terminal keyboard
    wget_wstr(3x) - get an array of wide characters from a curses terminal keyboard
    what(1p) - identify SCCS files (DEVELOPMENT)
    whatis(1) - display one-line manual page descriptions
    whereis(1) - locate the binary, source, and manual page files for a command
    whline(3x) - create curses borders, horizontal and vertical lines
    whline_set(3x) - create curses borders or lines using complex characters and renditions
    who(1) - show who is logged on
    who(1p) - display who is on the system
    whoami(1) - print effective userid
    winch(3x) - get a character and attributes from a curses window
    winchnstr(3x) - get a string of characters (and attributes) from a curses window
    winchstr(3x) - get a string of characters (and attributes) from a curses window
    windmc(1) - generates Windows message resources.
    windres(1) - manipulate Windows resources.
    winnstr(3x) - get a string of characters from a curses window
    winnwstr(3x) - get a string of wchar_t characters from a curses window
    winsch(3x) - insert a character before cursor in a curses window
    winsdelln(3x) - delete and insert lines in a curses window
    winsertln(3x) - delete and insert lines in a curses window
    winsnstr(3x) - insert string before cursor in a curses window
    wins_nwstr(3x) - insert a wide-character string into a curses window
    winsstr(3x) - insert string before cursor in a curses window
    winstr(3x) - get a string of characters from a curses window
    wins_wch(3x) - insert a complex character and rendition into a window
    wins_wstr(3x) - insert a wide-character string into a curses window
    win_wch(3x) - extract a complex character and rendition from a window
    win_wchnstr(3x) - get an array of complex characters and renditions from a curses window
    win_wchstr(3x) - get an array of complex characters and renditions from a curses window
    winwstr(3x) - get a string of wchar_t characters from a curses window
    wipefs(8) - wipe a signature from a device
    wmemchr(3) - search a wide character in a wide-character array
    wmemchr(3p) - find a wide character in memory
    wmemcmp(3) - compare two arrays of wide-characters
    wmemcmp(3p) - compare wide characters in memory
    wmemcpy(3) - copy an array of wide-characters
    wmemcpy(3p) - copy wide characters in memory
    wmemmove(3) - copy an array of wide-characters
    wmemmove(3p) - copy wide characters in memory with overlapping areas
    wmempcpy(3) - copy memory area
    wmemset(3) - fill an array of wide-characters with a constant wide character
    wmemset(3p) - set wide characters in memory
    wmouse_trafo(3x) - mouse interface through curses
    wmove(3x) - move curses window cursor
    wnoutrefresh(3x) - refresh curses windows and lines
    wordexp(3) - perform word expansion like a posix-shell
    wordexp(3p) - perform word expansions
    wordexp.h(0p) - expansion types
    wordfree(3) - perform word expansion like a posix-shell
    wordfree(3p) - perform word expansions
    wprintf(3) - formatted wide-character output conversion
    wprintf(3p) - character output
    wprintw(3x) - print formatted output in curses windows
    wredrawln(3x) - refresh curses windows and lines
    wrefresh(3x) - refresh curses windows and lines
    wresize(3x) - resize a curses window
    write(1) - send a message to another user
    write(1p) - write to another user
    write(2) - write to a file descriptor
    write(3p) - write on a file
    writev(2) - read or write data into multiple buffers
    writev(3p) - write a vector
    wscanf(3p) - character input
    wscanw(3x) - convert formatted input from a curses window
    wscrl(3x) - scroll a curses window
    wsetscrreg(3x) - curses output options
    wsrep_sst_common(1) - common command line parser to be sourced by other SST scripts
    wsrep_sst_mariabackup(1) - mariabackup-based state snapshot transfer
    wsrep_sst_mysqldump(1) - mysqldump-based state snapshot transfer
    wsrep_sst_rsync(1) - rsync-based state snapshot transfer
    wsrep_sst_rsync_wan(1) - rsync_wan (rsync with delta transfers)-based state snapshot transfer
    wsrep_sst_xtrabackup-v2(1) - xtrabackup-based state snapshot transfer
    wsrep_sst_xtrabackup(1) - xtrabackup-based state snapshot transfer
    wstandend(3x) - curses character and window attribute control routines
    wstandout(3x) - curses character and window attribute control routines
    wsyncdown(3x) - create curses windows
    wsyncup(3x) - create curses windows
    wtimeout(3x) - curses input options
    wtmp(5) - login records
    wtouchln(3x) - curses refresh control routines
    wunctrl(3x) - miscellaneous curses utility routines
    wvline(3x) - create curses borders, horizontal and vertical lines
    wvline_set(3x) - create curses borders or lines using complex characters and renditions

top
    x25(7) - ITU-T X.25 / ISO-8208 protocol interface.
    x86_64(8) - change reported architecture in new program environment and/or set personality flags
    xargs(1) - build and execute command lines from standard input
    xargs(1p) - construct argument lists and invoke utility
    xattr(7) - Extended attributes
    x_contexts(5) - userspace SELinux labeling interface and configuration file format for the X Window System contexts backend. This backend is also used to determine the default context for labeling remotely connected X clients
    xcrypt(3) - RFS password encryption
    xdecrypt(3) - RFS password encryption
    xdr(3) - library routines for external data representation
    xdr_accepted_reply(3) - library routines for remote procedure calls
    xdr_array(3) - library routines for external data representation
    xdr_authunix_parms(3) - library routines for remote procedure calls
    xdr_bool(3) - library routines for external data representation
    xdr_bytes(3) - library routines for external data representation
    xdr_callhdr(3) - library routines for remote procedure calls
    xdr_callmsg(3) - library routines for remote procedure calls
    xdr_char(3) - library routines for external data representation
    xdr_destroy(3) - library routines for external data representation
    xdr_double(3) - library routines for external data representation
    xdr_enum(3) - library routines for external data representation
    xdr_float(3) - library routines for external data representation
    xdr_free(3) - library routines for external data representation
    xdr_getpos(3) - library routines for external data representation
    xdr_inline(3) - library routines for external data representation
    xdr_int(3) - library routines for external data representation
    xdr_long(3) - library routines for external data representation
    xdrmem_create(3) - library routines for external data representation
    xdr_opaque(3) - library routines for external data representation
    xdr_opaque_auth(3) - library routines for remote procedure calls
    xdr_pmap(3) - library routines for remote procedure calls
    xdr_pmaplist(3) - library routines for remote procedure calls
    xdr_pointer(3) - library routines for external data representation
    xdrrec_create(3) - library routines for external data representation
    xdrrec_endofrecord(3) - library routines for external data representation
    xdrrec_eof(3) - library routines for external data representation
    xdrrec_skiprecord(3) - library routines for external data representation
    xdr_reference(3) - library routines for external data representation
    xdr_rejected_reply(3) - library routines for remote procedure calls
    xdr_replymsg(3) - library routines for remote procedure calls
    xdr_setpos(3) - library routines for external data representation
    xdr_short(3) - library routines for external data representation
    xdrstdio_create(3) - library routines for external data representation
    xdr_string(3) - library routines for external data representation
    xdr_u_char(3) - library routines for external data representation
    xdr_u_int(3) - library routines for external data representation
    xdr_u_long(3) - library routines for external data representation
    xdr_union(3) - library routines for external data representation
    xdr_u_short(3) - library routines for external data representation
    xdr_vector(3) - library routines for external data representation
    xdr_void(3) - library routines for external data representation
    xdr_wrapstring(3) - library routines for external data representation
    xencrypt(3) - RFS password encryption
    xfs(5) - layout, mount options, and supported file attributes for the XFS filesystem
    xfs_admin(8) - change parameters of an XFS filesystem
    xfs_bmap(8) - print block mapping for an XFS file
    xfs_copy(8) - copy the contents of an XFS filesystem
    xfsctl(3) - control XFS filesystems and individual files
    xfs_db(8) - debug an XFS filesystem
    xfsdump(8) - XFS filesystem incremental dump utility
    xfs_estimate(8) - estimate the space that an XFS filesystem will take
    xfs_freeze(8) - suspend access to an XFS filesystem
    xfs_fsr(8) - filesystem reorganizer for XFS
    xfs_growfs(8) - expand an XFS filesystem
    xfs_info(8) - display XFS filesystem geometry information
    xfsinvutil(8) - xfsdump inventory database checking and pruning utility
    xfs_io(8) - debug the I/O path of an XFS filesystem
    xfs_logprint(8) - print the log of an XFS filesystem
    xfs_mdrestore(8) - restores an XFS metadump image to a filesystem image
    xfs_metadump(8) - copy XFS filesystem metadata to a file
    xfs_mkfile(8) - create an XFS file
    xfs_ncheck(8) - generate pathnames from i-numbers for XFS
    xfs_quota(8) - manage use of quota on XFS filesystems
    xfs_repair(8) - repair an XFS filesystem
    xfsrestore(8) - XFS filesystem incremental restore utility
    xfs_rtcp(8) - XFS realtime copy command
    xfs_scrub(8) - check and repair the contents of a mounted XFS filesystem
    xfs_scrub_all(8) - scrub all mounted XFS filesystems
    xfs_spaceman(8) - show free space information about an XFS filesystem
    xgettext(1) - extract gettext strings from source
    xprt_register(3) - library routines for remote procedure calls
    xprt_unregister(3) - library routines for remote procedure calls
    xqmstats(8) - Display XFS quota manager statistics from /proc
    xt(8) - tc iptables action
    xtables-legacy(8) - iptables using old getsockopt/setsockopt-based kernel api
    xtables-monitor(8) - show changes to rule set and trace-events
    xtables-nft(8) - iptables using nftables kernel api
    xtables-translate(8) - translation tools to migrate from iptables to nftables

top
    y0(3) - Bessel functions of the second kind
    y0(3p) - Bessel functions of the second kind
    y0f(3) - Bessel functions of the second kind
    y0l(3) - Bessel functions of the second kind
    y1(3) - Bessel functions of the second kind
    y1(3p) - Bessel functions of the second kind
    y1f(3) - Bessel functions of the second kind
    y1l(3) - Bessel functions of the second kind
    yacc(1p) - yet another compiler compiler (DEVELOPMENT)
    yes(1) - output a string repeatedly until killed
    yn(3) - Bessel functions of the second kind
    yn(3p) - Bessel functions of the second kind
    ynf(3) - Bessel functions of the second kind
    ynl(3) - Bessel functions of the second kind
    ypdomainname(1) - show or set the system's host name
    yum-aliases(1) - yum aliases plugin
    yum-builddep(1) - install missing dependencies for building an RPM package
    yum-changelog(1) - changelog
    yum-changelog.conf(5) - changelog.conf(5)
    yum-complete-transaction(8) - attempt to complete failed or aborted Yum transactions
    yum-config-manager(1) - manage yum configuration options and yum repositories
    yum-copr(8) - YUM copr Plugin
    yum-cron(8) - an interface to conveniently call yum from cron
    yum-debug-dump(1) - write system RPM configuration to a debug-dump file
    yum-debug-restore(1) - replay Yum transactions captured in a debug-dump file
    yum-filter-data(1) - yum filter data plugin
    yum-fs-snapshot(1) - fs-snapshot
    yum-fs-snapshot.conf(5) - fs-snapshot.conf(5)
    yum-groups-manager(1) - create and edit yum's group metadata
    yum-list-data(1) - yum list data plugin
    yum-ovl(1) - Performs an initial copy-up of yum(8) package database.
    yum-plugin-copr(8) - YUM copr Plugin
    yum-shell(8) - Yellowdog Updater Modified shell
    yum-updatesd(8) - Update notifier daemon
    yum-updatesd.conf(5) - Configuration file for yum-updatesd(8).
    yum-utils(1) - tools for manipulating repositories and extended package management
    yum-verify(1) - yum verify plugin
    yum-versionlock(1) - Version lock rpm packages
    yum-versionlock.conf(5) - versionlock.conf(5)
    yum(8) - Yellowdog Updater Modified
    yum.conf(5) - Configuration file for yum(8).
    yumdb(8) - query and alter the Yum database
    yumdownloader(1) - download RPM packages from Yum repositories

top
    zbxpcp(3) - Zabbix Agent Loadable PCP Module
    zcat(1p) - expand and concatenate data
    zdump(8) - timezone dumper
    zenmap(1) - Graphical Nmap frontend and results viewer
    zero(4) - data sink
    zic(8) - timezone compiler
    zos-remote.conf(5) - the audisp-racf plugin configuration file
    zramctl(8) - set up and control zram devices
    zsoelim(1) - satisfy .so requests in roff input
"""

regex = re.compile(r"\s+([\w\d\-_\.]+)\((\d)(\w?)\)", re.IGNORECASE)

MANPAGE = filter(lambda x: x,
                 map(lambda x: re.search(regex, x),
                     MANPAGE.split("\n")))

def create_link(n, d, suffix):
    """ Creates a link from the name of the manpage.

    This hasn't been tested extensively, as there are 10k+ links... but it's
    worked for the handful that I tried?
    """
    return (n, f"http://man7.org/linux/man-pages/man{d}/{n}.{d}{suffix}.html")

results = dict(map(lambda x: create_link(*x.groups()), MANPAGE))
pprint(results, open("output", "w"))
