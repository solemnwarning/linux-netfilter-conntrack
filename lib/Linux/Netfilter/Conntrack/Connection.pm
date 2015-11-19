=head1 NAME

Linux::Netfilter::Conntrack::Connection - Connection tracking table entry

=head1 DESCRIPTION

This class wraps the C<nf_conntrack> structure which represents a single entry
in the connection tracking table.

All methods in this class throw an untyped (string) exception on error.

=cut

use strict;
use warnings;

package Linux::Netfilter::Conntrack::Connection;

use Carp;
use Socket qw(AF_INET inet_ntop inet_pton);

require XSLoader;
XSLoader::load("Linux::Netfilter::Conntrack::Connection");

use overload
	'""' => sub
	{
		my ($self) = @_;

		return $self->snprintf(Linux::Netfilter::Conntrack::NFCT_T_UNKNOWN(),
			Linux::Netfilter::Conntrack::NFCT_O_DEFAULT(),
			Linux::Netfilter::Conntrack::NFCT_OF_SHOW_LAYER3());
	};

# List of attributes to copy when exporting/importing. It is assumed a get_XXX
# and set_XXX method exists for each which behaves in the usual way.
my @EXPORT_ATTRS = (
	"orig_ipv4_src",
	"orig_ipv4_dst",
	"repl_ipv4_src",
	"repl_ipv4_dst",
	"orig_ipv6_src",
	"orig_ipv6_dst",
	"repl_ipv6_src",
	"repl_ipv6_dst",
	"orig_port_src",
	"orig_port_dst",
	"repl_port_src",
	"repl_port_dst",
	"icmp_type",
	"icmp_code",
	"icmp_id",
	"orig_l3proto",
	"repl_l3proto",
	"orig_l4proto",
	"repl_l4proto",
	"tcp_state",
	"snat_ipv4",
	"dnat_ipv4",
	"snat_port",
	"dnat_port",
	"timeout",
	"mark",
	"orig_counter_packets",
	"repl_counter_packets",
	"orig_counter_bytes",
	"repl_counter_bytes",
	"use",
	"id",
	"status",
	"tcp_flags_orig",
	"tcp_flags_repl",
	"tcp_mask_orig",
	"tcp_mask_repl",
	"master_ipv4_src",
	"master_ipv4_dst",
	"master_ipv6_src",
	"master_ipv6_dst",
	"master_port_src",
	"master_port_dst",
	"master_l3proto",
	"master_l4proto",
	# "secmark",
	# "orig_nat_seq_correction_pos",
	# "orig_nat_seq_offset_before",
	# "orig_nat_seq_offset_after",
	# "repl_nat_seq_correction_pos",
	# "repl_nat_seq_offset_before",
	# "repl_nat_seq_offset_after",
	"sctp_state",
	# "sctp_vtag_orig",
	# "sctp_vtag_repl",
	"helper_name",
	"dccp_state",
	"dccp_role",
	# "dccp_handshake_seq",
	"tcp_wscale_orig",
	"tcp_wscale_repl",
	"zone",
	# "secctx",
	"timestamp_start",
	"timestamp_stop",
);

=head1 CLASS METHODS

=head2 new()

Create a new nf_conntrack structure.

Returns a C<Linux::Netfilter::Conntrack::Connection> object.

=head2 new_from_export($data)

Construct a new C<nf_conntrack> structure from one previously exported using
the C<export()> method.

Returns a C<Linux::Netfilter::Conntrack::Connection> object.

=cut

sub new_from_export
{
	my ($class, $data) = @_;

	my $self = $class->new();

	foreach my $attr(@EXPORT_ATTRS)
	{
		if(defined($data->{$attr}))
		{
			my $set = "set_$attr";
			$self->$set($data->{$attr});
		}
		else{
			my $unset = "unset_$attr";
			$self->$unset();
		}
	}

	return $self;
}

=head1 INSTANCE METHODS

=head2 clone()

Create a copy of an existing nf_conntrack structure.

Returns a C<Linux::Netfilter::Conntrack::Connection> object.

=head2 get_xxx()

Returns the string representation of attribute xxx, undef if unset.

Integer types will be represented as plain base-10 integers, IP address types
will be formatted by the host C<inet_ntop()> function.

The following attributes are implemented:

=over

=item orig_ipv4_src

=item orig_ipv4_dst

=item repl_ipv4_src

=item repl_ipv4_dst

=item orig_ipv6_src

=item orig_ipv6_dst

=item repl_ipv6_src

=item repl_ipv6_dst

=item orig_port_src

=item orig_port_dst

=item repl_port_src

=item repl_port_dst

=item icmp_type

=item icmp_code

=item icmp_id

=item orig_l3proto

=item repl_l3proto

=item orig_l4proto

=item repl_l4proto

=item tcp_state

=item snat_ipv4

=item dnat_ipv4

=item snat_port

=item dnat_port

=item timeout

=item mark

=item orig_counter_packets

=item repl_counter_packets

=item orig_counter_bytes

=item repl_counter_bytes

=item use

=item id

=item status

=item tcp_flags_orig

=item tcp_flags_repl

=item tcp_mask_orig

=item tcp_mask_repl

=item master_ipv4_src

=item master_ipv4_dst

=item master_ipv6_src

=item master_ipv6_dst

=item master_port_src

=item master_port_dst

=item master_l3proto

=item master_l4proto

=item sctp_state

=item helper_name

=item dccp_state

=item dccp_role

=item tcp_wscale_orig

=item tcp_wscale_repl

=item zone

=item secctx (READ ONLY)

=item timestamp_start

=item timestamp_stop

=back

Consult the Netfilter documentation for their meanings.

=head2 set_xxx($value)

Set the value of attribute xxx, takes a string in the same format as returned
by the C<get_xxx()> methods.

=head2 unset_xxx()

Unset attribute xxx, if set.

=head2 snprintf($msg_type, $out_type, $flags)

Dump the C<nf_conntrack> structure to a buffer and return it as a string.

From the C<libnetfilter_conntrack> documentation:

If you are listening to events, probably you want to display the message type as
well. In that case, set the message type parameter to any of the known existing
types, ie. C<NFCT_T_NEW>, C<NFCT_T_UPDATE>, C<NFCT_T_DESTROY>. If you pass
C<NFCT_T_UNKNOWN>, the message type will not be output.

Currently, the output available are:

  NFCT_O_DEFAULT: default /proc-like output
  NFCT_O_XML:     XML output

The output flags are:

  NFCT_OF_SHOW_LAYER3
      include layer 3 information in the output, this is *only* required by
      NFCT_O_DEFAULT.
  
  NFCT_OF_TIME
      display time.

=head2 export()

Dump the C<nf_conntrack> data structure to an unblessed Perl data structure
suitable for passing through JSON or similar and reconstructing on the other
end.

=cut

sub export
{
	my ($self) = @_;

	my $data = {
		map {
			my $method = "get_$_";
			($_ => $self->$method());
		} @EXPORT_ATTRS
	};

	delete $data->{$_}
		foreach(grep { !defined $data->{$_} } keys(%$data));

	return $data;
}

=head1 BUGS

The following functions do not yet have wrappers:

  set_attr_grp
  get_attr_grp
  attr_grp_is_set
  attr_grp_unset

=cut

1;
