use strict;
use warnings;

open(STDOUT, ">", $ARGV[0])
	or die "Cannot open ".$ARGV[0].": $!";

print <<EOF;
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

MODULE = Linux::Netfilter::Conntrack::Connection PACKAGE = Linux::Netfilter::Conntrack::Connection

struct nf_conntrack* new(const char *class)
	CODE:
		RETVAL = nfct_new();
		if(RETVAL == NULL)
		{
			croak("nfct_new: %s", strerror(errno));
		}

	OUTPUT:
		RETVAL

struct nf_conntrack *clone(struct nf_conntrack *self)
	CODE:
		RETVAL = nfct_clone(self);
		if(RETVAL == NULL)
		{
			croak("nfct_clone: %s", strerror(errno));
		}

	OUTPUT:
		RETVAL

void DESTROY(struct nf_conntrack *self)
	CODE:
		nfct_destroy(self);

SV *snprintf(struct nf_conntrack *self, unsigned int msg_type, unsigned int out_type, unsigned int flags)
	CODE:
		/* Arbitrary buffer size taken from source of 'conntrack' tool. */
		char buf[1024];

		// TODO: Can this error? Docs don't say.
		nfct_snprintf(buf, sizeof(buf), self, msg_type, out_type, flags);

		RETVAL = newSVpv(buf, 0);

	OUTPUT:
		RETVAL

EOF

ipv4_attr_funcs("ATTR_ORIG_IPV4_SRC");
ipv4_attr_funcs("ATTR_ORIG_IPV4_DST");
ipv4_attr_funcs("ATTR_REPL_IPV4_SRC");
ipv4_attr_funcs("ATTR_REPL_IPV4_DST");

ipv6_attr_funcs("ATTR_ORIG_IPV6_SRC");
ipv6_attr_funcs("ATTR_ORIG_IPV6_DST");
ipv6_attr_funcs("ATTR_REPL_IPV6_SRC");
ipv6_attr_funcs("ATTR_REPL_IPV6_DST");

be16_attr_funcs("ATTR_ORIG_PORT_SRC");
be16_attr_funcs("ATTR_ORIG_PORT_DST");
be16_attr_funcs("ATTR_REPL_PORT_SRC");
be16_attr_funcs("ATTR_REPL_PORT_DST");

u8_attr_funcs("ATTR_ICMP_TYPE");
u8_attr_funcs("ATTR_ICMP_CODE");

# libnetfilter_conntrack src/conntrack/snprintf_default.c implies this is
# probably big endian.
be16_attr_funcs("ATTR_ICMP_ID");

u8_attr_funcs("ATTR_ORIG_L3PROTO");
u8_attr_funcs("ATTR_REPL_L3PROTO");
u8_attr_funcs("ATTR_ORIG_L4PROTO");
u8_attr_funcs("ATTR_REPL_L4PROTO");
u8_attr_funcs("ATTR_TCP_STATE");

ipv4_attr_funcs("ATTR_SNAT_IPV4");
ipv4_attr_funcs("ATTR_DNAT_IPV4");

be16_attr_funcs("ATTR_SNAT_PORT");
be16_attr_funcs("ATTR_DNAT_PORT");

u32_attr_funcs("ATTR_TIMEOUT");
u32_attr_funcs("ATTR_MARK");

filthy_u64_attr_funcs("ATTR_ORIG_COUNTER_PACKETS");
filthy_u64_attr_funcs("ATTR_REPL_COUNTER_PACKETS");
filthy_u64_attr_funcs("ATTR_ORIG_COUNTER_BYTES");
filthy_u64_attr_funcs("ATTR_REPL_COUNTER_BYTES");

u32_attr_funcs("ATTR_USE");
u32_attr_funcs("ATTR_ID");
u32_attr_funcs("ATTR_STATUS");

u8_attr_funcs("ATTR_TCP_FLAGS_ORIG");
u8_attr_funcs("ATTR_TCP_FLAGS_REPL");
u8_attr_funcs("ATTR_TCP_MASK_ORIG");
u8_attr_funcs("ATTR_TCP_MASK_REPL");

ipv4_attr_funcs("ATTR_MASTER_IPV4_SRC");
ipv4_attr_funcs("ATTR_MASTER_IPV4_DST");

ipv6_attr_funcs("ATTR_MASTER_IPV6_SRC");
ipv6_attr_funcs("ATTR_MASTER_IPV6_DST");

be16_attr_funcs("ATTR_MASTER_PORT_SRC");
be16_attr_funcs("ATTR_MASTER_PORT_DST");

u8_attr_funcs("ATTR_MASTER_L3PROTO");
u8_attr_funcs("ATTR_MASTER_L4PROTO");

# ATTR_SECMARK,				/* u32 bits */
# ATTR_ORIG_NAT_SEQ_CORRECTION_POS,	/* u32 bits */
# ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE,	/* u32 bits */
# ATTR_ORIG_NAT_SEQ_OFFSET_AFTER = 48,	/* u32 bits */
# ATTR_REPL_NAT_SEQ_CORRECTION_POS,	/* u32 bits */
# ATTR_REPL_NAT_SEQ_OFFSET_BEFORE,	/* u32 bits */
# ATTR_REPL_NAT_SEQ_OFFSET_AFTER,	/* u32 bits */

u8_attr_funcs("ATTR_SCTP_STATE");

# ATTR_SCTP_VTAG_ORIG,			/* u32 bits */
# ATTR_SCTP_VTAG_REPL,			/* u32 bits */

string_attr_funcs("ATTR_HELPER_NAME");

u8_attr_funcs("ATTR_DCCP_STATE");
u8_attr_funcs("ATTR_DCCP_ROLE");

# ATTR_DCCP_HANDSHAKE_SEQ,		/* u64 bits */

u8_attr_funcs("ATTR_TCP_WSCALE_ORIG");
u8_attr_funcs("ATTR_TCP_WSCALE_REPL");

u16_attr_funcs("ATTR_ZONE");

string_attr_funcs("ATTR_SECCTX");

filthy_u64_attr_funcs("ATTR_TIMESTAMP_START");
filthy_u64_attr_funcs("ATTR_TIMESTAMP_STOP");

sub ipv4_attr_funcs
{
	my ($attr) = @_;

	(my $name = lc($attr)) =~ s/^attr_//;

	print <<EOF;
SV *get_$name(struct nf_conntrack *self)
	CODE:
		const uint32_t *value = nfct_get_attr(self, $attr);
		if(value != NULL)
		{
			char buf[INET_ADDRSTRLEN];
			if(inet_ntop(AF_INET, value, buf, sizeof(buf)) == NULL)
			{
				croak("inet_ntop: %s", strerror(errno));
			}

			RETVAL = newSVpv(buf, 0);
		}
		else{
			if(errno == ENODATA)
			{
				XSRETURN_UNDEF;
			}
			else{
				croak("nfct_get_attr: %s", strerror(errno));
			}
		}

	OUTPUT:
		RETVAL

void set_$name(struct nf_conntrack *self, const char *value)
	CODE:
		uint32_t buf;
		if(inet_pton(AF_INET, value, &buf) == 1)
		{
			nfct_set_attr(self, $attr, &buf);
		}
		else{
			croak("Invalid IPv4 address '%s'", value);
		}

void unset_$name(struct nf_conntrack *self)
	CODE:
		nfct_attr_unset(self, $attr);

EOF
}

sub ipv6_attr_funcs
{
	my ($attr) = @_;

	(my $name = lc($attr)) =~ s/^attr_//;

	print <<EOF;
SV *get_$name(struct nf_conntrack *self)
	CODE:
		const void *value = nfct_get_attr(self, $attr);
		if(value != NULL)
		{
			char buf[INET6_ADDRSTRLEN];
			if(inet_ntop(AF_INET6, value, buf, sizeof(buf)) == NULL)
			{
				croak("inet_ntop: %s", strerror(errno));
			}

			RETVAL = newSVpv(buf, 0);
		}
		else{
			if(errno == ENODATA)
			{
				XSRETURN_UNDEF;
			}
			else{
				croak("nfct_get_attr: %s", strerror(errno));
			}
		}

	OUTPUT:
		RETVAL

void set_$name(struct nf_conntrack *self, const char *value)
	CODE:
		unsigned char buf[16]; /* IPv6 addr, 128 bits, 16 bytes */
		if(inet_pton(AF_INET6, value, &buf) == 1)
		{
			nfct_set_attr(self, $attr, &buf);
		}
		else{
			croak("Invalid IPv6 address '%s'", value);
		}

void unset_$name(struct nf_conntrack *self)
	CODE:
		nfct_attr_unset(self, $attr);

EOF
}

sub be16_attr_funcs
{
	my ($attr) = @_;

	(my $name = lc($attr)) =~ s/^attr_//;

	print <<EOF;
uint16_t get_$name(struct nf_conntrack *self)
	CODE:
		const uint16_t *value = nfct_get_attr(self, $attr);
		if(value != NULL)
		{
			RETVAL = be16toh(*value);
		}
		else{
			if(errno == ENODATA)
			{
				XSRETURN_UNDEF;
			}
			else{
				croak("nfct_get_attr: %s", strerror(errno));
			}
		}

	OUTPUT:
		RETVAL

void set_$name(struct nf_conntrack *self, uint16_t value)
	CODE:
		nfct_set_attr_u16(self, $attr, htobe16(value));

void unset_$name(struct nf_conntrack *self)
	CODE:
		nfct_attr_unset(self, $attr);

EOF
}

sub u8_attr_funcs
{
	my ($attr) = @_;
	uX_attr_funcs($attr, 8);
}

sub u16_attr_funcs
{
	my ($attr) = @_;
	uX_attr_funcs($attr, 16);
}

sub u32_attr_funcs
{
	my ($attr) = @_;
	uX_attr_funcs($attr, 32);
}

sub u64_attr_funcs
{
	my ($attr) = @_;
	uX_attr_funcs($attr, 64);
}

sub uX_attr_funcs
{
	my ($attr, $bits) = @_;

	(my $name = lc($attr)) =~ s/^attr_//;

	print <<EOF;
uint${bits}_t get_$name(struct nf_conntrack *self)
	CODE:
		const uint${bits}_t *value = nfct_get_attr(self, $attr);
		if(value != NULL)
		{
			RETVAL = *value;
		}
		else{
			if(errno == ENODATA)
			{
				XSRETURN_UNDEF;
			}
			else{
				croak("nfct_get_attr: %s", strerror(errno));
			}
		}

	OUTPUT:
		RETVAL

void set_$name(struct nf_conntrack *self, uint${bits}_t value)
	CODE:
		nfct_set_attr_u${bits}(self, $attr, value);

void unset_$name(struct nf_conntrack *self)
	CODE:
		nfct_attr_unset(self, $attr);

EOF
}

# Some attributes are read-only in libnetfilter_conntrack, but not for any
# strong reason... conviniently there's a combination of an encapsulation hole
# and a bug we can take advantage of... hahaha :(
#
# Need to send them a patch to make this redundant sometime...

sub filthy_u64_attr_funcs
{
	my ($attr) = @_;
	filthy_uX_attr_funcs($attr, 64);
}

sub filthy_uX_attr_funcs
{
	my ($attr, $bits) = @_;

	(my $name = lc($attr)) =~ s/^attr_//;

	print <<EOF;
uint${bits}_t get_$name(struct nf_conntrack *self)
	CODE:
		const uint${bits}_t *value = nfct_get_attr(self, $attr);
		if(value != NULL)
		{
			RETVAL = *value;
		}
		else{
			if(errno == ENODATA)
			{
				XSRETURN_UNDEF;
			}
			else{
				croak("nfct_get_attr: %s", strerror(errno));
			}
		}

	OUTPUT:
		RETVAL

void set_$name(struct nf_conntrack *self, uint${bits}_t value)
	CODE:
		/* Won't set the value, but will set the bit saying the value
		 * has been set...
		*/
		nfct_set_attr_u${bits}(self, $attr, value);

		/* ...then we can get a pointer to it, strip the const.... */

		uint${bits}_t *vptr = (uint${bits}_t*)(nfct_get_attr(self, $attr));
		if(vptr == NULL)
		{
			croak("nfct_get_attr: %s", strerror(errno));
		}

		/* ...and actually set the value. */

		*vptr = value;

void unset_$name(struct nf_conntrack *self)
	CODE:
		nfct_attr_unset(self, $attr);

EOF
}

sub string_attr_funcs
{
	my ($attr, $bits) = @_;

	(my $name = lc($attr)) =~ s/^attr_//;

	print <<EOF;
SV *get_$name(struct nf_conntrack *self)
	CODE:
		const char *value = nfct_get_attr(self, $attr);
		if(value != NULL)
		{
			RETVAL = newSVpv(value, 0);
		}
		else{
			if(errno == ENODATA)
			{
				XSRETURN_UNDEF;
			}
			else{
				croak("nfct_get_attr: %s", strerror(errno));
			}
		}

	OUTPUT:
		RETVAL

void set_$name(struct nf_conntrack *self, const char *value)
	CODE:
		nfct_set_attr(self, $attr, value);

void unset_$name(struct nf_conntrack *self)
	CODE:
		nfct_attr_unset(self, $attr);

EOF
}
