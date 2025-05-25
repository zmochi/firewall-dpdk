#include <cassert>

#include "conn_table.hpp"
#include "packet.hpp"

decision_info conn_table::tcp_new_conn(pkt_props     props,
                                       decision_info static_rt_dc) {
    /* this function should only be called when ACK = 0. otherwise call function
     * that handles ACK = 1 */
    assert(!(props.tcp_flags & TCP_ACK_FLAG));

    if ( !(props.tcp_flags & TCP_SYN_FLAG) ) {
        return decision_info(-1, PKT_DROP, REASON_STATEFUL_INVALID);
    }

    assert(static_rt_dc.reason == REASON_RULE ||
           static_rt_dc.reason == REASON_NO_RULE);
    conn_table_entry new_entry = conn_table_entry(props, TWH_SYN_SENT);
    new_entry.rule_idx = static_rt_dc.rule_idx;

    if ( lookup_entry(new_entry) != nullptr ) {
        return decision_info(-1, PKT_DROP, REASON_STATEFUL_CONN_EXISTS);
    }

    add_entry(new_entry);
    // client_reorder.init_seq(props.seq_nb);

    /* retain original decision, since static ruletable might have stored rule
     * index in decision_info, we can't make a new decision_info instance */
    return static_rt_dc;
}

enum conn_action_t {
    PASS,
    REMOVE_ENTRY,
    BAD_PKT,
};

#include <iostream>

#ifdef TCP_STATE_MACHINE_LOGGING
#include "utils.h"
#else
#define LOG(x, ...) (void)0
#endif

std::string stringify_state(state_t state) {
    switch ( state ) {
        case STATE_NUL:
            return "STATE_NUL";
        case TWH_SYN_SENT:
            return "TWH_SYN_SENT";
        case TWH_SYN_ACK_RECEIVED:
            return "TWH_SYN_ACK_RECEIVED";
        case TWH_SYN_ACK_SENT:
            return "TWH_SYN_ACK_SENT";
        case TWH_ACK_RECEIVED:
            return "TWH_ACK_RECEIVED";
        case CONN_ESTABLISHED:
            return "CONN_ESTABLISHED";
        case FIN_SENT:
            return "FIN_SENT";
        case FIN_ACKED:
            return "FIN_ACKED";
        default:
            throw std::runtime_error("unknown new_state");
    };
}

void update_state(state_t &state, state_t new_state, bool client) {
    std::string new_state_str = stringify_state(new_state);
    std::string old_state_str = stringify_state(state);
    LOG("%s: %s -> %s", client ? "client" : "server", old_state_str.c_str(),
        new_state_str.c_str());
    state = new_state;
}

static conn_action_t advance_client_state(conn_table_entry &entry,
                                          pkt_props         props) {
    bool     PKT_SYN = static_cast<bool>(props.tcp_flags & TCP_SYN_FLAG);
    bool     PKT_FIN = static_cast<bool>(props.tcp_flags & TCP_FIN_FLAG);
    state_t &server_state = entry.server_state;
    state_t &client_state = entry.client_state;

    switch ( client_state ) {
            /* this is the starting condition, set by tcp_new_conn() when the
             * client sends the first SYN packet. */
        case TWH_SYN_SENT:
            if ( PKT_SYN ) {
                std::cout << "Not implemented" << std::endl;
                assert(true);
                /* re-transmission of SYN */
                /* the following line is problematic since anyone can hijack the
                 * connection by sending a spoofed SYN packet right after the
                 * client's SYN */
                // client_reorder.init_seq(props.seq_nb);
            }
            /* client sent ACK in response to server SYN/ACK */
            if ( server_state != TWH_SYN_ACK_SENT ) {
                std::cout << "Impossible scenario!" << std::endl;
                return BAD_PKT;
            }
            update_state(client_state, CONN_ESTABLISHED, true);
            update_state(server_state, CONN_ESTABLISHED, false);
            break;
        case CONN_ESTABLISHED:
            if ( PKT_FIN ) {
                update_state(client_state, FIN_SENT, true);
                entry.client_fin = props.seq_nb;
                if ( server_state == FIN_SENT &&
                     props.ack_nb >= entry.server_fin ) {
                    update_state(server_state, FIN_ACKED, false);
                }
            }
            break;
        case FIN_SENT:
            if ( PKT_FIN ) {
                /* FIN re-transmission */
                LOG("client: FIN re-transmission");
                entry.client_fin = props.seq_nb;
            } else if ( server_state == FIN_SENT &&
                        entry.server_fin <= props.ack_nb ) {
                update_state(server_state, FIN_ACKED, false);
            } else {
                throw std::runtime_error(
                    "fin was sent (state is FIN_SENT), but outgoing packet "
                    "not ack'ing client FIN. shouldn't happen... ");
            }
            break;
        case FIN_ACKED:
            /* this must be the last ACK */
            if ( server_state == FIN_SENT &&
                 entry.server_fin <= props.ack_nb ) {
                update_state(server_state, FIN_ACKED, false);
            }
            return REMOVE_ENTRY;

        default:
            return BAD_PKT;
    }

    return PASS;
}

static conn_action_t advance_server_state(conn_table_entry &entry,
                                          pkt_props         props) {
    bool     PKT_SYN = static_cast<bool>(props.tcp_flags & TCP_SYN_FLAG);
    bool     PKT_FIN = static_cast<bool>(props.tcp_flags & TCP_FIN_FLAG);
    state_t &server_state = entry.server_state;
    state_t &client_state = entry.client_state;
    switch ( server_state ) {
        case STATE_NUL:
            if ( !PKT_SYN ) {
                // in this state server should send SYN/ACK
                assert(true);
            }
            update_state(server_state, TWH_SYN_ACK_SENT, false);
            /* set server sequence number (client sequence number is set
             * by ordering mechanism, when client syn is sent) */
            // server_reorder.init_seq(props.seq_nb);
            break;
        case TWH_SYN_ACK_SENT:
            if ( !PKT_SYN ) {
                /* client code below should have transferred server to
                 * ESTABLISHED state, after sending final TWH ack.
                 * shouldn't happen */
                assert(true);
            }
            /* re-transmission of SYN/ACK */
            // server_reorder.init_seq(props.seq_nb);
            break;
        case CONN_ESTABLISHED:
            if ( PKT_FIN ) {
                update_state(server_state, FIN_SENT, false);
                entry.server_fin = props.seq_nb;
                /* server sent FIN/ACK in response to client FIN */
                if ( client_state == FIN_SENT &&
                     props.ack_nb >= entry.client_fin ) {
                    update_state(client_state, FIN_ACKED, true);
                }
            }
            break;
        case FIN_SENT:
            if ( PKT_FIN ) {
                /* FIN re-transmission */
                entry.server_fin = props.seq_nb;
            } else if ( client_state == FIN_SENT &&
                        entry.client_fin < props.ack_nb ) {
                update_state(client_state, FIN_ACKED, true);
            } else {
                /* fin was sent (state is FIN_SENT), but outgoing packet not
                 * ack'ing server FIN. shouldn't happen... */
                assert(true);
            }
            break;
        case FIN_ACKED:
            /* this must be the lact ACK */
            if ( client_state == FIN_SENT && entry.client_fin < props.ack_nb ) {
                update_state(client_state, FIN_ACKED, true);
            }
            return REMOVE_ENTRY;

        default:
            return BAD_PKT;
    }

    return PASS;
}

decision_info conn_table::tcp_existing_conn(pkt_props props) {
    /* this function should only be called when ACK = 1 */
    assert(props.tcp_flags & TCP_ACK_FLAG);
    conn_table_entry *pkt_entry = lookup_entry(conn_table_entry(props));

    /* ACK == 1 but no entry in connection table */
    if ( pkt_entry == nullptr ) {
		LOG("pkt_entry == nullptr");
        return decision_info(PKT_DROP, REASON_STATEFUL_INVALID);
    } else if ( props.tcp_flags & TCP_RST_FLAG ) {
		LOG("removing entry..");
        remove_entry(*pkt_entry);
        return decision_info(PKT_PASS, REASON_STATEFUL_RST);
    }

    bool from_client = props.saddr == pkt_entry->client_addr &&
                       props.sport == pkt_entry->client_port;
    bool from_server = props.saddr == pkt_entry->server_addr &&
                       props.sport == pkt_entry->server_port;
    assert(from_server || from_client);

    if ( from_server ) {
        switch ( advance_server_state(*pkt_entry, props) ) {
            case PASS:
                break;
            case REMOVE_ENTRY:
                remove_entry(*pkt_entry);
                break;
            case BAD_PKT:
                [[fallthrough]];
            default:
                return decision_info(PKT_DROP, REASON_STATEFUL_INVALID);
        }
    } else if ( from_client ) {
        switch ( advance_client_state(*pkt_entry, props) ) {
            case PASS:
                break;
            case REMOVE_ENTRY:
                remove_entry(*pkt_entry);
                break;
            case BAD_PKT:
                [[fallthrough]];
            default:
                return decision_info(PKT_DROP, REASON_STATEFUL_INVALID);
        }
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
