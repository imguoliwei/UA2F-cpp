//#define SELECT_IPV6

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
extern "C" {
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#ifndef SELECT_IPV6
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#else
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#endif
#include <libnetfilter_queue/pktbuff.h>
}

constexpr char UA_PADDING = 'F';
#ifndef SELECT_IPV6
constexpr char UA_STR[] = "XiaoYuanWang4/2.0";
#else
constexpr char UA_STR[] = "XiaoYuanWang6/2.0";
#endif
constexpr size_t UA_STR_LENGTH = sizeof(UA_STR) - 1;
const size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE >> 1);
using std::unique_ptr;

static int child_status;
static mnl_socket *nl;
static long long tcpCount = 0;
static long long uaMark = 0;
static long long noUAMark = 0;
static int uaEmpty = 0;
static int uaFrag = 0;
static time_t start_t;
static char timeStr[60];
static unique_ptr<char[]> str;

static char* strNCaseStr(const char * const s1, const size_t n1, const char * const s2, const size_t n2) {
    /* we need something to compare */
    if (n1 == 0 || n2 == 0)
        return nullptr;

    /* "s2" must be smaller or equal to "s1" */
    if (n1 < n2)
        return nullptr;

    /* the last position where its possible to find "s2" in "s1" */
    const char * const last = s1 + n1 - n2;

    for (const char *cur = s1; cur <= last; ++cur)
        if (*cur == *s2 && strncasecmp(cur, s2, n2) == 0)
            return const_cast<char*>(cur);

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
static void nfq_send_verdict(const int queue_num, const uint32_t id, pkt_buff * const pktb, const uint32_t mark, const bool noUA) {
    char buf[0xffff + (MNL_SOCKET_BUFFER_SIZE >> 1)];
    nlattr *nest;

    auto const nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

    if (pktb_mangled(pktb)) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }

    if (noUA) {
        if (mark == 1) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(16));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark >= 16 && mark <= 40) {
            auto const setmark = mark + 1;
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark == 41) { // 21 统计确定此连接为不含UA连接
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(43));
            mnl_attr_nest_end(nlh, nest); // 加 CONNMARK
            ++noUAMark;
        }
    } else {
        if (mark != 44) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(44));
            mnl_attr_nest_end(nlh, nest);
            ++uaMark;
        }
    }

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 1.");
        exit(EXIT_FAILURE);
    }

    ++tcpCount;
    pktb_free(pktb);
}

static bool modify_ua(const char *const uaPointer, const char *const tcpPkPayload, const unsigned int tcpPkLen, pkt_buff *const pktb) {
    const unsigned int uaOffset = uaPointer - tcpPkPayload + 14; // 应该指向 UA 的第一个字符
    if (uaOffset > tcpPkLen - 2) {
        syslog(LOG_WARNING, "User-Agent has no content or too short in this packet");
        ++uaEmpty;
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
        ++uaFrag;
        return false;
    }
#ifndef SELECT_IPV6
    if (nfq_tcp_mangle_ipv4(pktb, uaOffset, uaLength, str.get(), uaLength) == 1) {
#else
    if (nfq_tcp_mangle_ipv6(pktb, uaOffset, uaLength, str.get(), uaLength) == 1) {
#endif
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

    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    auto const nfg = static_cast<const nfgenmsg*>(mnl_nlmsg_get_payload(nlh));

    if (attr[NFQA_PACKET_HDR] == nullptr) {
        syslog(LOG_ERR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_CT]) {
        mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctAttr);
        if (ctAttr[CTA_MARK]) {
            mark = ntohl(mnl_attr_get_u32(ctAttr[CTA_MARK]));
        } else {
            mark = 1; // no mark 1
        } // NFQA_CT 一定存在，不存在说明有其他问题
    }

    auto const ph = static_cast<const nfqnl_msg_packet_hdr*>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));
    auto const pLen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    auto const payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
#ifndef SELECT_IPV6
    auto const pktb = pktb_alloc(AF_INET, payload, pLen, 0); //IP包
#else
    auto const pktb = pktb_alloc(AF_INET6, payload, pLen, 0); //IPv6包
#endif
    if (!pktb) {
        syslog(LOG_ERR, "pktb malloc failed");
        return MNL_CB_ERROR;
    }
#ifndef SELECT_IPV6
    auto const ipPkHdl = nfq_ip_get_hdr(pktb); //获取IP header
    if (nfq_ip_set_transport_header(pktb, ipPkHdl) < 0) {
#else
    auto const ipPkHdl = nfq_ip6_get_hdr(pktb); //获取IPv6 header
    if (nfq_ip6_set_transport_header(pktb, ipPkHdl, IPPROTO_TCP) != 1) {
#endif
        syslog(LOG_ERR, "set transport header failed");
        pktb_free(pktb);
        return MNL_CB_ERROR;
    }

    auto const tcpPkHdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    auto const tcpPkPayload = static_cast<const char*>(nfq_tcp_get_payload(tcpPkHdl, pktb)); //获取 tcp载荷
    auto const tcpPkLen = nfq_tcp_get_payload_len(tcpPkHdl, pktb); //获取 tcp长度

    static long long uaCount = 0;
    if (tcpPkPayload) {
        const char * const uaPointer = strNCaseStr(tcpPkPayload, tcpPkLen, "\r\nUser-Agent: ", 14); // 找到指向 \r 的指针
        if (uaPointer) {
            modify_ua(uaPointer, tcpPkPayload, tcpPkLen, pktb) ? ++uaCount : 0;
        } else {
            noUA = true;
        }
    }
    nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, noUA);

    static long long httpCount = 4;
    if (uaCount == (httpCount << 1) || uaCount - httpCount >= 8192) {
        httpCount = uaCount;
        const time_t current_t = time(nullptr);
        time2str(static_cast<int>(difftime(current_t, start_t)));
        syslog(LOG_INFO,
#ifndef SELECT_IPV6
               "UA2F has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s. There are %d empty and %d fragment. ",
#else
               "UA2F6 has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s. There are %d empty and %d fragment. ",
#endif
               uaCount, tcpCount, uaMark, noUAMark, timeStr, uaEmpty, uaFrag);
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
    if(argc < 2){
#ifndef SELECT_IPV6
        printf("UA2F Usage: %s queue_number\n", argv[0]);
#else
        printf("UA2F6 Usage: %s queue_number\n", argv[0]);
#endif
        exit(EXIT_FAILURE);
    }
    const int queue_number = atoi(argv[1]);
    printf("Current queue_number is %d\n", queue_number);
    signal(SIGTERM, killChild);

    int errCount = 0;
    while (true) {
        child_status = fork();
#ifndef SELECT_IPV6
        openlog("UA2F", LOG_CONS | LOG_PID, LOG_SYSLOG);
#else
        openlog("UA2F6", LOG_CONS | LOG_PID, LOG_SYSLOG);
#endif
        if (child_status < 0) {
            syslog(LOG_ERR, "Failed to give birth.");
            syslog(LOG_ERR, "Exit at breakpoint 2.");
            exit(EXIT_FAILURE);
        } else if (child_status == 0) {
#ifndef SELECT_IPV6
            syslog(LOG_NOTICE, "UA2F processor start at [%d].", getpid());
#else
            syslog(LOG_NOTICE, "UA2F6 processor start at [%d].", getpid());
#endif
            break;
        } else {
#ifndef SELECT_IPV6
            syslog(LOG_NOTICE, "Try to start UA2F processor at [%d].", child_status);
#else
            syslog(LOG_NOTICE, "Try to start UA2F6 processor at [%d].", child_status);
#endif
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
#ifndef SELECT_IPV6
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
#else
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);
#endif

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
#ifndef SELECT_IPV6
    syslog(LOG_NOTICE, "UA2F has inited successful.");
#else
    syslog(LOG_NOTICE, "UA2F6 has inited successful.");
#endif

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
