use ExtUtils::H2PM;

module "Linux::Netfilter::Conntrack";

include "sys/types.h";
include "libnetfilter_conntrack/libnetfilter_conntrack.h";

constant "NFNL_SUBSYS_CTNETLINK";
constant "NFNL_SUBSYS_CTNETLINK_EXP";
constant "NFNL_SUBSYS_NONE";

constant "NFCT_ALL_CT_GROUPS";
constant "NF_NETLINK_CONNTRACK_NEW";
constant "NF_NETLINK_CONNTRACK_UPDATE";
constant "NF_NETLINK_CONNTRACK_DESTROY";

constant "NFCT_T_UNKNOWN";
constant "NFCT_T_NEW";
constant "NFCT_T_UPDATE";
constant "NFCT_T_DESTROY";
constant "NFCT_T_ALL";
constant "NFCT_T_ERROR";

constant "NFCT_CB_STOP";
constant "NFCT_CB_CONTINUE";

constant "NFCT_O_DEFAULT";
constant "NFCT_O_XML";

constant "NFCT_OF_SHOW_LAYER3";
constant "NFCT_OF_TIME";

constant "NFCT_Q_CREATE";
constant "NFCT_Q_UPDATE";
constant "NFCT_Q_DESTROY";
constant "NFCT_Q_GET";
constant "NFCT_Q_FLUSH";
constant "NFCT_Q_DUMP";
constant "NFCT_Q_DUMP_RESET";
constant "NFCT_Q_CREATE_UPDATE";

write_output $ARGV[0];
