#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <variant>
#include <functional>
extern "C" {
#include <unistd.h>
#include <syslog.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/pktbuff.h>
}

constexpr char UA_PADDING = 'F';
constexpr char UA_STR[] = "XiaoYuanWang/2.1";
constexpr size_t UA_STR_LENGTH = sizeof(UA_STR) - 1;
constexpr bool CLEAR_TCP_TIMESTAMPS = false;
const size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE >> 1);
using std::unique_ptr;
using std::function;
using std::variant;
using std::get;

static int child_status;
static mnl_socket *nl;
static time_t start_t;
static char timeStr[60];
static unique_ptr<char[]> str;

class UA2F_status{
public:
    long long tcpCount = 0;
    long long uaMark = 0;
    long long noUAMark = 0;
    long long uaCount = 0;
    int uaEmpty = 0;
    int uaFrag = 0;
    [[nodiscard]] bool shouldPrint() const {
        return uaCount == (httpCount << 1) || uaCount - httpCount >= 8192;
    }
    void increaseCounter() {
        httpCount = uaCount;
    }
private:
    long long httpCount = 1;
};

class TcpOptionsScanner {
public:
    explicit TcpOptionsScanner(const tcphdr * const tcpPkHdl) :
    tcpOptionsStart(reinterpret_cast<const char*>(tcpPkHdl) + sizeof(tcphdr)),
    curr(tcpOptionsStart),
    bound(reinterpret_cast<const char*>(tcpPkHdl) + tcpPkHdl->doff * 4)
    {}

    [[nodiscard]] bool hasNext() const { return curr < bound; }

    void next(){
        if(!hasNext()) throw std::out_of_range("TcpOptionsScanner out of bound");
        if(*curr == TCPOPT_NOP){
            ++curr;
        } else {
            curr += curr[1];
        }
    }

    [[nodiscard]] const char * getCurrOption() const {
        return curr;
    }

private:
    const char * const tcpOptionsStart;
    const char * curr;
    const char * const bound;
};

static char* strNCaseStr(const char * const s1, const size_t n1, const char * const s2, const size_t n2) {
    /* we need something to compare */
    if (n1 == 0 || n2 == 0)
        return nullptr;

    /* "s2" must be smaller or equal to "s1" */
    if (n1 < n2)
        return nullptr;

    /* the last position where its possible to find "s2" in "s1" */
    const char * const last = s1 + n1 - n2;

    for (const char *cur = s1; cur <= last; ++cur){
        if (*cur == *s2 && strncasecmp(cur, s2, n2) == 0)
            return const_cast<char*>(cur);
    }
    return nullptr;
}

static char* time2str(const int sec) {
    memset(timeStr, 0, sizeof(timeStr));
    if (sec <= 60) {
        sprintf(timeStr, "%d seconds", sec);
    } else if (sec <= 3600) {
        sprintf(timeStr, "%d minutes and %d seconds", sec / 60, sec % 60);
    } else if (sec <= 86400) {
        sprintf(timeStr, "%d hours, %d minutes and %d seconds", sec / 3600, sec % 3600 / 60, sec % 60);
    } else {
        sprintf(timeStr, "%d days, %d hours, %d minutes and %d seconds", sec / 86400, sec % 86400 / 3600,
                sec % 3600 / 60,
                sec % 60);
    }
    return timeStr;
}

static int parse_attrs(const nlattr * const attr, void * const data) {
    auto const tb = static_cast<const nlattr**>(data);
    auto const type = mnl_attr_get_type(attr);
    tb[type] = attr;
    return MNL_CB_OK;
}

// http mark = 24, ukn mark = 16-20, no http mark = 23
static void nfq_send_verdict(const int queue_num, const uint32_t id, pkt_buff * const pktb, const uint32_t mark, const bool noUA, UA2F_status& currStatus) {
    char buf[sizeof_buf];

    auto const nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

    if (pktb_mangled(pktb)) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }

    auto const nest = mnl_attr_nest_start(nlh, NFQA_CT);
    if (noUA) {
        switch (mark) {
            case 1:
                mnl_attr_put_u32(nlh, CTA_MARK, htonl(16));
                break;
            case 16 ... 40:
                {
                    auto const setmark = mark + 1;
                    mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
                }
                break;
            case 41:
                mnl_attr_put_u32(nlh, CTA_MARK, htonl(43));
                ++currStatus.noUAMark;
                break;
            default:
                break;
        }
    } else {
        if (mark != 44) {
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(44));
            ++currStatus.uaMark;
        }
    }
    mnl_attr_nest_end(nlh, nest);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 1.");
        exit(EXIT_FAILURE);
    }

    ++currStatus.tcpCount;
}

static bool clearTcpTimestamps(tcphdr *const tcpPkHdl, pkt_buff *const pktb, const bool isIPv4){
    if(tcpPkHdl->doff * 4 == sizeof(tcphdr)) return false;
    TcpOptionsScanner optScanner(tcpPkHdl);
    while (optScanner.hasNext()){
        auto const curr = optScanner.getCurrOption();
        if(*curr == TCPOPT_TIMESTAMP){
            variant<iphdr*, ip6_hdr*> ipPkHdl;
            if(isIPv4){
                ipPkHdl = nfq_ip_get_hdr(pktb);
            } else {
                ipPkHdl = nfq_ip6_get_hdr(pktb);
            }
            const unsigned int dataOffset = reinterpret_cast<const char*>(tcpPkHdl) - (
                    isIPv4 ?
                    reinterpret_cast<const char*>(get<iphdr*>(ipPkHdl)) :
                    reinterpret_cast<const char*>(get<ip6_hdr*>(ipPkHdl))
                    );
            const unsigned int matchOffset = curr - reinterpret_cast<const char*>(tcpPkHdl);
            char padding[TCPOLEN_TIMESTAMP];
            memset(padding, TCPOPT_NOP, TCPOLEN_TIMESTAMP);
            const bool nfq_tcp_mangle_succeed = (
                    isIPv4 ?
                    nfq_ip_mangle(pktb, dataOffset, matchOffset, TCPOLEN_TIMESTAMP, padding, TCPOLEN_TIMESTAMP) :
                    nfq_ip6_mangle(pktb, dataOffset, matchOffset, TCPOLEN_TIMESTAMP, padding, TCPOLEN_TIMESTAMP)
                    ) == 1;
            if(nfq_tcp_mangle_succeed){
                if(isIPv4){
                    nfq_tcp_compute_checksum_ipv4(tcpPkHdl, get<iphdr*>(ipPkHdl));
                } else {
                    nfq_tcp_compute_checksum_ipv6(tcpPkHdl, get<ip6_hdr*>(ipPkHdl));
                }
                return true;
            } else {
                syslog(LOG_ERR, "failed at clearTcpTimestamps.");
                return false;
            }
        }
        optScanner.next();
    }
    return false;
}

static bool modify_ua(const char *const uaPointer, const char *const tcpPkPayload, const unsigned int tcpPkLen, pkt_buff *const pktb, const bool isIPv4, UA2F_status& currStatus) {
    const unsigned int uaOffset = uaPointer - tcpPkPayload + 14; // 应该指向 UA 的第一个字符
    if (uaOffset > tcpPkLen - 2) {
        syslog(LOG_WARNING, "User-Agent has no content or too short in this packet");
        ++currStatus.uaEmpty;
        return false;
    }
    unsigned int uaLength = 0;
    const char * const uaStartPointer = uaPointer + 14;
    const unsigned int uaLengthBound = tcpPkLen - uaOffset;
    for (unsigned int i = 0; i < uaLengthBound; ++i) {
        if (*(uaStartPointer + i) == '\r') {
            uaLength = i;
            break;
        }
    }
    if(uaLength == 0) {
        ++currStatus.uaFrag;
        return false;
    }
    const bool nfq_tcp_mangle_succeed = (
            isIPv4 ?
            nfq_tcp_mangle_ipv4(pktb, uaOffset, uaLength, str.get(), uaLength) :
            nfq_tcp_mangle_ipv6(pktb, uaOffset, uaLength, str.get(), uaLength)
            ) == 1;
    if (nfq_tcp_mangle_succeed) {
        return true;
    } else {
        syslog(LOG_ERR, "Mangle packet failed.");
        return false;
    }
}

static int queue_cb(const nlmsghdr * const nlh, void * const) {
    nlattr *attr[NFQA_MAX + 1] = {};
    nlattr *ctAttr[CTA_MAX + 1] = {};
    uint32_t mark = 0;
    bool noUA = false;

    if (nfq_nlmsg_parse(nlh, attr) == MNL_CB_ERROR) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    auto const nfg = static_cast<const nfgenmsg*>(mnl_nlmsg_get_payload(nlh));

    if (attr[NFQA_PACKET_HDR] == nullptr) {
        syslog(LOG_ERR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_CT] != nullptr) {
        mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctAttr);
        if (ctAttr[CTA_MARK] != nullptr) {
            mark = ntohl(mnl_attr_get_u32(ctAttr[CTA_MARK]));
        } else {
            mark = 1; // no mark 1
        } // NFQA_CT 一定存在，不存在说明有其他问题
    }

    auto const ph = static_cast<const nfqnl_msg_packet_hdr*>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));
    auto const pLen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    auto const payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
    const bool isIPv4 = ntohs(ph->hw_protocol) == ETHERTYPE_IP;
    const bool isIPv6 = ntohs(ph->hw_protocol) == ETHERTYPE_IPV6;
    if(!(isIPv4 || isIPv6)){
        syslog(LOG_ERR, "Unsupported netfilter packet protocol family");
        return MNL_CB_ERROR;
    }

    static UA2F_status IPv4Status, IPv6Status;
    auto& currStatus = isIPv4 ? IPv4Status : IPv6Status;
    unique_ptr<pkt_buff, function<void(pkt_buff*)>> pktb {
        pktb_alloc(isIPv4 ? AF_INET : AF_INET6, payload, pLen, 0), //IP包
        [](pkt_buff * const p){
            if(p != nullptr) pktb_free(p);
        }
    };

    if (pktb == nullptr) {
        syslog(LOG_ERR, "pktb malloc failed");
        return MNL_CB_ERROR;
    }
    //auto const ipPkHdl = nfq_ip_get_hdr(pktb.get()); //获取IP header
    //auto const ip6PkHdl = nfq_ip6_get_hdr(pktb.get()); //获取IPv6 header
    variant<iphdr*, ip6_hdr*> ipPkHdl;
    if(isIPv4){
        ipPkHdl = nfq_ip_get_hdr(pktb.get());
    } else {
        ipPkHdl = nfq_ip6_get_hdr(pktb.get());
    }
    const bool nfq_ip_set_transport_header_succeed = isIPv4 ?
            (nfq_ip_set_transport_header(pktb.get(), get<iphdr*>(ipPkHdl)) == 0) :
            (nfq_ip6_set_transport_header(pktb.get(), get<ip6_hdr*>(ipPkHdl), IPPROTO_TCP) == 1);
    if (!nfq_ip_set_transport_header_succeed) {
        syslog(LOG_ERR, "set transport header failed");
        return MNL_CB_ERROR;
    }

    auto const tcpPkHdl = nfq_tcp_get_hdr(pktb.get()); //获取 tcp header
    if(tcpPkHdl == nullptr){
        syslog(LOG_ERR, "Transport Layer Error");
        return MNL_CB_ERROR;
    }
    auto const tcpPkPayload = static_cast<const char*>(nfq_tcp_get_payload(tcpPkHdl, pktb.get())); //获取 tcp载荷
    if (tcpPkPayload != nullptr) {
        auto const tcpPkLen = nfq_tcp_get_payload_len(tcpPkHdl, pktb.get()); //获取 tcp长度
        const char * const uaPointer = strNCaseStr(tcpPkPayload, tcpPkLen, "\r\nUser-Agent: ", 14); // 找到指向 \r 的指针
        if (uaPointer != nullptr) {
            modify_ua(uaPointer, tcpPkPayload, tcpPkLen, pktb.get(), isIPv4, currStatus) ? ++currStatus.uaCount : 0;
        } else {
            noUA = true;
        }
    }
    if(CLEAR_TCP_TIMESTAMPS) clearTcpTimestamps(tcpPkHdl, pktb.get(), isIPv4);
    nfq_send_verdict(ntohs(nfg->res_id), ntohl(static_cast<uint32_t>(ph->packet_id)), pktb.get(), mark, noUA, currStatus);

    if (currStatus.shouldPrint()) {
        currStatus.increaseCounter();
        const time_t current_t = time(nullptr);
        time2str(static_cast<int>(difftime(current_t, start_t)));
        auto const logStr = isIPv4 ?
                "UA2F has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s. There are %d empty and %d fragment. " :
                "UA2F6 has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s. There are %d empty and %d fragment. ";
        syslog(LOG_INFO, logStr,
               currStatus.uaCount, currStatus.tcpCount, currStatus.uaMark, currStatus.noUAMark, timeStr, currStatus.uaEmpty, currStatus.uaFrag);
    }

    return MNL_CB_OK;
}

static void killChild(const int) {
    syslog(LOG_INFO, "Received SIGTERM, kill child %d", child_status);
    kill(child_status, SIGKILL); // Not graceful, but work
    mnl_socket_close(nl);
    exit(EXIT_SUCCESS);
}

int main(const int argc, const char * const * const argv) {
    if(argc != 2){
        printf("UA2F Usage: %s queue_number\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const int queue_number = atoi(argv[1]);
    printf("Current queue_number is %d\n", queue_number);
    signal(SIGTERM, killChild);

    int errCount = 0;
    while (true) {
        child_status = fork();
        openlog("UA2F", LOG_CONS | LOG_PID, LOG_SYSLOG);
        if (child_status < 0) {
            syslog(LOG_ERR, "Failed to give birth.");
            syslog(LOG_ERR, "Exit at breakpoint 2.");
            exit(EXIT_FAILURE);
        } else if (child_status == 0) {
            syslog(LOG_NOTICE, "UA2F processor start at [%d].", getpid());
            break;
        } else {
            syslog(LOG_NOTICE, "Try to start UA2F processor at [%d].", child_status);
            int deadStat;
            const int deadPid = wait(&deadStat);
            if (deadPid == -1) {
                syslog(LOG_ERR, "Child suicide.");
            } else {
                syslog(LOG_ERR, "Meet fatal error.[%d] dies by %d", deadPid, deadStat);
            }
        }
        if (++errCount > 10) {
            syslog(LOG_ERR, "Meet too many fatal error, no longer try to recover.");
            syslog(LOG_ERR, "Exit at breakpoint 3.");
            exit(EXIT_FAILURE);
        }
    }

    start_t = time(nullptr);

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == nullptr) {
        perror("mnl_socket_open");
        syslog(LOG_ERR, "Exit at breakpoint 4.");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        syslog(LOG_ERR, "Exit at breakpoint 5.");
        exit(EXIT_FAILURE);
    }
    auto const portid = mnl_socket_get_portid(nl);

    unique_ptr<char[]> buf {new char[sizeof_buf]};
    str.reset(new char[sizeof_buf]);
    memset(str.get(), UA_PADDING, sizeof_buf);
    memcpy(str.get(), UA_STR, UA_STR_LENGTH);

    auto nlh = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 7.");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_FLAGS,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_MASK,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 8.");
        exit(EXIT_FAILURE);
    }

    ssize_t ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));
    syslog(LOG_NOTICE, "UA2F has inited successful.");

    while (true) {
        ret = mnl_socket_recvfrom(nl, buf.get(), sizeof_buf);
        if (ret == -1) { //stop at failure
            perror("mnl_socket_recvfrom");
            syslog(LOG_ERR, "Exit at breakpoint 9.");
            exit(EXIT_FAILURE);
        }
        ret = mnl_cb_run(buf.get(), ret, 0, portid, queue_cb, nullptr);
        if (ret < 0) { //stop at failure
            perror("mnl_cb_run");
            syslog(LOG_ERR, "Exit at breakpoint 10.");
            exit(EXIT_FAILURE);
        }
    }
}