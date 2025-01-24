#include "conn_table.hpp"
#include "packet.hpp"

#include <cassert>
decision_info conn_table::tcp_new_conn(pkt_props     props,
                                       decision_info static_rt_dc) {
    /* this function should only be called when ACK = 0. otherwise call function
     * that handles ACK = 1 */
    assert(!(props.tcp_flags & TCP_ACK_FLAG));

    if ( !(props.tcp_flags & TCP_SYN_FLAG) ) {
        return decision_info(-1, PKT_DROP, REASON_STATEFUL_INVALID);
    }

    assert(static_rt_dc.reason == REASON_RULE);
    conn_table_entry new_entry = conn_table_entry(props, SYN_SENT);
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
    /* this function should only be called when ACK = 1 */
    assert(props.tcp_flags & TCP_ACK_FLAG);
    conn_table_entry *pkt_entry = lookup_entry(conn_table_entry(props));

    /* ACK == 1 but no entry in connection table */
    if ( pkt_entry == nullptr ) {
        return decision_info(PKT_DROP, REASON_STATEFUL_INVALID);
    } else if ( props.tcp_flags & TCP_RST_FLAG ) {
        remove_entry(*pkt_entry);
        return decision_info(PKT_PASS, REASON_STATEFUL_RST);
    }

    bool from_client = props.saddr == pkt_entry->client_addr &&
                       props.sport == pkt_entry->client_port;
    bool from_server = props.saddr == pkt_entry->server_addr &&
                       props.sport == pkt_entry->server_port;
    assert(from_server || from_client);
    state_t state = pkt_entry->state;
    bool    PKT_SYN = static_cast<bool>(props.tcp_flags & TCP_SYN_FLAG);
    bool    PKT_FIN = static_cast<bool>(props.tcp_flags & TCP_FIN_FLAG);

	if(PKT_FIN && (state == SYN_RECEIVED || state == ESTABLISHED)) {
		if(from_client)
			pkt_entry->client_fin = props.seq_nb;
		else // from_server
			pkt_entry->server_fin = props.seq_nb;
	} 
	if(from_server && pkt_entry->client_fin < props.ack_nb ) {
		// server returned ack on client fin
		pkt_entry->client_fin_ack = true;
	}

	else if(from_client && pkt_entry->server_fin < props.ack_nb ) {
		// client returned ack on server fin
		pkt_entry->server_fin_ack = true;
	}
    if ( from_client ) {
        /* fin/ack from client after syn/ack from server */
        if ( PKT_FIN && (state == SYN_RECEIVED || state == ESTABLISHED) ) {
            /* this combination means: client waiting for server ack and
             * possibly fin */
            pkt_entry->client_fin = true;
            pkt_entry->state = FIN_WAIT_1;
        } else if ( !PKT_FIN && state == FIN_WAIT_1 ) {
            /* ack from server: client waiting for server fin */
            pkt_entry->state = FIN_WAIT_2;
        } else if ( PKT_FIN && state == FIN_WAIT_1 ) {
            /* fin/ack from server: server waiting for client ack */
			pkt_entry->state = CLOSING;
        } else if (!PKT_FIN && state == FIN_WAIT_1 ) {

		}
    } else if ( PKT_FIN && from_server ) {
    }

    if ( PKT_SYN && state == SYN_SENT && from_server) {
        /* move from received syn -> sent syn/ack */
		pkt_entry->server_seq = props.seq_nb;
		assert(pkt_entry->client_seq > 0);
        pkt_entry->state = SYN_RECEIVED;
    } else if ( !PKT_SYN && state == SYN_RECEIVED && from_client ) {
        /* moved from sent syn/ack -> server received ack, connection
         * established */
        pkt_entry->state = ESTABLISHED;
    } else if ( !PKT_SYN && state == ESTABLISHED ) {
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

void conn_table::add_entry(conn_table_entry entry) { entries[entry] = entry; }

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
