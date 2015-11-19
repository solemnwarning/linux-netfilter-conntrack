=head1 NAME

Linux::Netfilter::Conntrack::Handle - Access the kernel connection tracking table.

=head1 DESCRIPTION

This class wraps the C<nfct_handle> structure and associated functions,
providing netlink access to the conntrack tables.

All methods in this class throw an untyped (string) exception on error.

=cut

use strict;
use warnings;

package Linux::Netfilter::Conntrack::Handle;

require XSLoader;
XSLoader::load("Linux::Netfilter::Conntrack::Handle");

=head1 CLASS METHODS

=head2 new($subsys_id, $subscriptions)

Create a new netlink/conntrack handle.

C<$subsys_id> should be one of the following:

=over

=item C<NFNL_SUBSYS_CTNETLINK> - Create handle for conntrack operations

=item C<NFNL_SUBSYS_CTNETLINK_EXP> - Create handle for expectation operations

=item C<NFNL_SUBSYS_NONE> - Create handle for conntrack I<and> expectation operations

=back

=head1 INSTANCE METHODS

=head2 fileno()

Return the file descriptor number of the netlink socket. Useful for monitoring
when a message is available using C<select()> or similar.

=head2 ct_callback_register($type, $callback)

Register a callback to process received conntrack entries.

  $handle->ct_callback_register(NFCT_T_ALL, sub
  {
	  my ($msg_type, $conn) = @_;
	  
	  # $msg_type - Message type (NFCT_T_NEW, NFCT_T_UPDATE, etc)
	  # $conn     - Linux::Netfilter::Conntrack::Connection object
	  
	  return NFCT_CB_STOP;     # Stop processing
	  return NFCT_CB_CONTINUE; # Continue processing
  }

Only one conntrack callback may be registered at a time.

=head2 ct_callback_unregister()

Unregister a callback function previously set with C<ct_callback_register>.

=head2 send($qt, $data)

Send a netlink message, C<$qt> should be a query type:

  NFCT_Q_FLUSH
  NFCT_Q_DUMP
  NFCT_Q_DUMP_RESET
  
    ^ $data argument must be a protocol family (e.g. AF_INET).
  
  NFCT_Q_CREATE
  NFCT_Q_UPDATE
  NFCT_Q_DESTROY
  NFCT_Q_GET
  NFCT_Q_CREATE_UPDATE
  
    ^ $data argument must be a L<Linux::Netfilter::Conntrack::Connection>.

=head2 catch()

Read and process messages from the netlink socket. Continues until the callback
returns C<NFCT_CB_STOP> or an error occurs.

=head2 query($qt, $data)

Send a netlink message (see C<send()>) and process the replies.

=cut

1;
