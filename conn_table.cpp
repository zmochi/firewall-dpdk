#include "conn_table.hpp"
#include "packet.hpp"

#include <cassert>
decision_info conn_table::tcp_new_conn(pkt_props     props,
                                       decision_info static_rt_dc) {
    assert(!(props.tcp_flags & TCP_ACK_FLAG));
    if ( !(props.tcp_flags & TCP_SYN_FLAG) ) {
        return decision_info(-1, PKT_DROP, REASON_STATEFUL_INVALID);
    }

    assert(static_rt_dc.reason == REASON_RULE);
    conn_table_entry new_entry = conn_table_entry(props, STATE_SYN);
    new_entry.rule_idx = static_rt_dc.rule_idx;

    if ( lookup_entry(new_entry) != nullptr ) {
        return decision_info(-1, PKT_DROP, REASON_STATEFUL_CONN_EXISTS);
    }

    add_entry(new_entry);

    /* retain original decision, since static ruletable might have stored rule
     * index in decision_info, we can't make a new decision_info instance */
    return static_rt_dc;
}

decision_info conn_table::tcp_existing_conn(pkt_props props) {
    conn_table_entry *pkt_entry = lookup_entry(conn_table_entry(props));

    /* ACK == 1 but no entry in connection table */
    if ( pkt_entry == nullptr ) {
        return decision_info(PKT_DROP, REASON_STATEFUL_INVALID);
    }

    state_t state = pkt_entry->state;
    bool    PKT_SYN = static_cast<bool>(props.tcp_flags & TCP_SYN_FLAG);

    if ( PKT_SYN && state == STATE_SYN ) {
        /* syn -> received syn/ack */
        pkt_entry->state = STATE_SYN_ACK;
    } else if ( !PKT_SYN && state == STATE_SYN_ACK ) {
        /* syn/ack -> received ack, connection established */
        pkt_entry->state = STATE_ESTABLISHED;
    } else if ( !PKT_SYN && state == STATE_ESTABLISHED ) {
        /* connection established, regular data transfer */
        // TODO: move to ftp/http tracking... also at syn_ack -> ack above?
    } else {
        return decision_info(PKT_DROP, REASON_STATEFUL_INVALID);
    }

    /* pass the packet with REASON_RULE so it'll be recorded in the same row
     * as the first packet of this connection */
    assert(pkt_entry->rule_idx >= 0);
    return decision_info(pkt_entry->rule_idx, PKT_PASS, REASON_RULE);
}

void conn_table::add_entry(conn_table_entry entry) {
    entries.emplace(std::make_pair(entry, entry));
}

conn_table_entry *conn_table::lookup_entry(conn_table_entry entry) {
    auto map_entry = entries.find(entry);
    if ( map_entry == entries.end() ) {
        return nullptr;
    }

    /* TODO: ensure that the returned pointer is "owned" by the caller, and
     * another caller can't get a pointer that is "owned" already. */
    return &map_entry->second;
}

void conn_table::remove_entry(conn_table_entry &entry) { entries.erase(entry); }
