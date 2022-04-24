#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <atomic>
#include <thread>
#include <variant>
#include <iostream>
#include <functional>
extern "C" {
#include <unistd.h>
#include <syslog.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
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

constexpr char UA_PADDING = ' ';
constexpr char UA_STR[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0";
constexpr size_t UA_BUFFER_LENGTH = 1500; //常见MTU
constexpr int NFQNL_COPY_PACKET_SIZE = 0xffff;
const size_t sizeof_buf = NFQNL_COPY_PACKET_SIZE + (MNL_SOCKET_BUFFER_SIZE / 2);
const time_t startTime = time(nullptr);
/*
 * 在未声明为 extern 的非局部非 volatile 非模板 (C++14 起)非 inline (C++17 起)变量声明上使用 const 限定符，会给予该变量内部连接。
 * 这有别于 C，其中 const 文件作用域对象拥有外部连接。
 * https://zh.cppreference.com/w/cpp/language/cv
 */
using std::unique_ptr;
using std::function;
using std::variant;
using std::get;
using std::cout;
using std::endl;
using std::thread;
using std::atomic;
using std::array;

static bool enableMangleUa = false;
static bool enableMangleUaBypass = false;
static bool enableClearTcpTimestamps = false;
static bool enableMangleIPv4Id = false;
static bool disableCtMark = false;

class UA2F_status{
public:
    long long tcpCount = 0;
    long long uaMark = 0;
    long long noUAMark = 0;
    long long uaCount = 0;
    long long uaBypass = 0;
    long long timestamps = 0;
    long long ipId = 0;
    int uaEmpty = 0;
    int uaFrag = 0;
    [[nodiscard]] bool shouldPrint() const {
        return uaCount == httpCount * 2;
    }
    void increaseCounter() {
        httpCount = uaCount;
    }
private:
    long long httpCount = 4;
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

template<size_t total_len, size_t ua_inner_length, size_t ua_length = ua_inner_length - 1, size_t result_inner_len = total_len + 1>
static constexpr array<char, result_inner_len> meta_cat_ua_and_padding(const char(&ua)[ua_inner_length], const char ch){
    static_assert(total_len > 0 && ua_inner_length > 0 && ua_length > 0 && total_len > ua_inner_length && result_inner_len > total_len);

    array<char, result_inner_len> result {};
    for(size_t i = 0; i < ua_length; ++i) result[i] = ua[i];
    for(size_t i = ua_length; i < total_len; ++i) result[i] = ch;
    return move(result);
}

template<size_t len, size_t inner_len = len + 1>
static constexpr array<char, inner_len> meta_strset(const char ch){
    static_assert(len > 0 && inner_len > len);

    array<char, inner_len> result {};
    for(size_t i = 0; i < len; ++i) result[i] = ch;
    return move(result);
}

static const char* strncasestr(const char * const s1, const size_t n1, const char * const s2, const size_t n2) {
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
            return cur;
    }
    return nullptr;
}

static char* time2str(const int sec, char* timeStr) {
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
static void nfq_send_verdict(const int queue_num, const uint32_t id, pkt_buff * const pktb, const uint32_t mark, const bool noUA, UA2F_status& currStatus, const mnl_socket * const nl) {
    char buf[sizeof_buf];
    auto const nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);
    if (pktb_mangled(pktb)) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }

    if(enableMangleUa && !disableCtMark){
        auto const nest = mnl_attr_nest_start(nlh, NFQA_CT);
        if (noUA) {
            if(mark == 1) {
                mnl_attr_put_u32(nlh, CTA_MARK, htonl(16));
            } else if(mark >= 16 && mark <= 40) {
                auto const setmark = mark + 1;
                mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
            } else if(mark == 41) {
                mnl_attr_put_u32(nlh, CTA_MARK, htonl(43));
                ++currStatus.noUAMark;
            }
        } else {
            if (mark != 44) {
                mnl_attr_put_u32(nlh, CTA_MARK, htonl(44));
                ++currStatus.uaMark;
            }
        }
        mnl_attr_nest_end(nlh, nest);
    }

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) == -1) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 1.");
        exit(EXIT_FAILURE);
    }

    ++currStatus.tcpCount;
}

static bool mangleIpv4Id(pkt_buff *const pktb){
    static atomic<decltype(iphdr::id)> currIpId = clock();
    auto const nextIpId = htons(++currIpId);
    auto const nextIpIdPtr = reinterpret_cast<const char*>(&nextIpId);
    constexpr static unsigned int matchOffset = offsetof(iphdr, id);
    constexpr static unsigned int len = sizeof(iphdr::id);
    static_assert(sizeof(nextIpId) == len);

    const bool succeed = nfq_ip_mangle(pktb, 0, matchOffset, len, nextIpIdPtr, len) == 1;
    if(succeed){
        return true;
    } else {
        syslog(LOG_ERR, "failed at mangleIpv4Id.");
        return false;
    }
}

static bool clearTcpTimestamps(pkt_buff *const pktb, const variant<iphdr*, ip6_hdr*>& ipPkHdl, tcphdr *const tcpPkHdl, const bool isIPv4){
    if(tcpPkHdl->doff * 4 == sizeof(tcphdr)) return false;
    for(TcpOptionsScanner optScanner(tcpPkHdl); optScanner.hasNext(); optScanner.next()){
        auto const curr = optScanner.getCurrOption();
        if(*curr != TCPOPT_TIMESTAMP) continue;
        const unsigned int dataOffset = reinterpret_cast<const char*>(tcpPkHdl) - (
                isIPv4 ?
                reinterpret_cast<const char*>(get<iphdr*>(ipPkHdl)) :
                reinterpret_cast<const char*>(get<ip6_hdr*>(ipPkHdl))
                );
        const unsigned int matchOffset = curr - reinterpret_cast<const char*>(tcpPkHdl);
        constexpr static auto padding = meta_strset<TCPOLEN_TIMESTAMP>(TCPOPT_NOP); //如果不加static则会在运行时初始化局部变量padding数组，产生大量不必要的指令
        const bool nfq_tcp_mangle_succeed = (
                isIPv4 ?
                nfq_ip_mangle(pktb, dataOffset, matchOffset, TCPOLEN_TIMESTAMP, padding.data(), TCPOLEN_TIMESTAMP) :
                nfq_ip6_mangle(pktb, dataOffset, matchOffset, TCPOLEN_TIMESTAMP, padding.data(), TCPOLEN_TIMESTAMP)
                ) == 1;
        if(!nfq_tcp_mangle_succeed){
            syslog(LOG_ERR, "failed at clearTcpTimestamps.");
            return false;
        }
        if(isIPv4){
            nfq_tcp_compute_checksum_ipv4(tcpPkHdl, get<iphdr*>(ipPkHdl));
        } else {
            nfq_tcp_compute_checksum_ipv6(tcpPkHdl, get<ip6_hdr*>(ipPkHdl));
        }
        return true;
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
        if (uaStartPointer[i] == '\r') {
            uaLength = i;
            break;
        }
    }
    if(uaLength == 0) {
        ++currStatus.uaFrag;
        return false;
    }
    constexpr static auto ua_result = meta_cat_ua_and_padding<UA_BUFFER_LENGTH>(UA_STR, UA_PADDING);
    const bool nfq_tcp_mangle_succeed = (
            isIPv4 ?
            nfq_tcp_mangle_ipv4(pktb, uaOffset, uaLength, ua_result.data(), uaLength) :
            nfq_tcp_mangle_ipv6(pktb, uaOffset, uaLength, ua_result.data(), uaLength)
            ) == 1;
    if (nfq_tcp_mangle_succeed) {
        ++currStatus.uaCount;
        return true;
    } else {
        syslog(LOG_ERR, "Mangle packet failed.");
        return false;
    }
}

static void mangleTcpPacket(pkt_buff *const pktb, const variant<iphdr*, ip6_hdr*>& ipPkHdl, tcphdr *const tcpPkHdl, const bool isIPv4, UA2F_status& currStatus, const uint32_t mark, bool& noUA){
    auto const tcpPkPayload = static_cast<const char*>(nfq_tcp_get_payload(tcpPkHdl, pktb)); //获取 tcp载荷
    if(tcpPkPayload == nullptr) return;

    if (enableMangleUa) {
        if(enableMangleUaBypass && mark == 43){
            ++currStatus.uaBypass;
        } else {
            auto const tcpPkLen = nfq_tcp_get_payload_len(tcpPkHdl, pktb); //获取 tcp长度
            const char * const uaPointer = strncasestr(tcpPkPayload, tcpPkLen, "\r\nUser-Agent: ", 14); // 找到指向 \r 的指针
            if (uaPointer != nullptr) {
                modify_ua(uaPointer, tcpPkPayload, tcpPkLen, pktb, isIPv4, currStatus);
                noUA = false;
            }
        }
    }

    if(enableClearTcpTimestamps && tcpPkHdl->th_flags == TH_SYN){
        clearTcpTimestamps(pktb, ipPkHdl, tcpPkHdl, isIPv4) ? ++currStatus.timestamps : 0;
    }
}

static int queue_cb(const nlmsghdr * const nlh, void * const data) {
    nlattr *attr[NFQA_MAX + 1] = {};
    if (nfq_nlmsg_parse(nlh, attr) == MNL_CB_ERROR) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }
    if (attr[NFQA_PACKET_HDR] == nullptr) {
        syslog(LOG_ERR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    uint32_t mark = 0;
    if (attr[NFQA_CT] != nullptr) {
        nlattr *ctAttr[CTA_MAX + 1] = {};
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

    const unique_ptr<pkt_buff, function<void(pkt_buff*)>> pktb {
        pktb_alloc(isIPv4 ? AF_INET : AF_INET6, payload, pLen, 0), //IP包
        [](pkt_buff * const p){
            if(p != nullptr) pktb_free(p);
        }
    };
    if (pktb == nullptr) {
        syslog(LOG_ERR, "pktb malloc failed");
        return MNL_CB_ERROR;
    }

    const variant<iphdr*, ip6_hdr*> ipPkHdl {
        isIPv4 ?
        variant<iphdr*, ip6_hdr*> { nfq_ip_get_hdr(pktb.get()) } :
        variant<iphdr*, ip6_hdr*> { nfq_ip6_get_hdr(pktb.get()) }
    };
    const bool nfq_ip_set_transport_header_succeed = isIPv4 ?
            (nfq_ip_set_transport_header(pktb.get(), get<iphdr*>(ipPkHdl)) == 0) :
            (nfq_ip6_set_transport_header(pktb.get(), get<ip6_hdr*>(ipPkHdl), IPPROTO_TCP) == 1);
    if (!nfq_ip_set_transport_header_succeed) {
        syslog(LOG_ERR, "set transport header failed");
        return MNL_CB_ERROR;
    }

    thread_local UA2F_status IPv4Status, IPv6Status;
    /*
     * 在块作用域声明且带有 static 或 thread_local (C++11 起) 说明符的变量拥有静态或线程 (C++11 起)存储期。
     * thread_local 关键词只能搭配在命名空间作用域声明的对象、在块作用域声明的对象及静态数据成员。它指示对象具有线程存储期。
     * 它能与 static 或 extern 结合，以分别指定内部或外部链接（但静态数据成员始终拥有外部链接），但额外的 static 不影响存储期。
     * https://zh.cppreference.com/w/cpp/language/storage_duration
     * 因此上面两个变量不需要加上 static
     */
    auto& currStatus = isIPv4 ? IPv4Status : IPv6Status;

    if(isIPv4 && enableMangleIPv4Id){
        mangleIpv4Id(pktb.get()) ? ++currStatus.ipId : 0;
    }

    bool noUA = true;
    if((isIPv4 && get<iphdr*>(ipPkHdl)->protocol == IPPROTO_TCP) || isIPv6){
        auto const tcpPkHdl = nfq_tcp_get_hdr(pktb.get()); //获取 tcp header
        if(tcpPkHdl == nullptr){
            syslog(LOG_ERR, "Transport Layer Error");
            return MNL_CB_ERROR;
        }

        mangleTcpPacket(pktb.get(), ipPkHdl, tcpPkHdl, isIPv4, currStatus, mark, noUA);
    }

    auto const nfg = static_cast<const nfgenmsg*>(mnl_nlmsg_get_payload(nlh));
    auto const currQueue = ntohs(nfg->res_id);
    auto const nl = static_cast<const mnl_socket*>(data);
    nfq_send_verdict(currQueue, ntohl(static_cast<uint32_t>(ph->packet_id)), pktb.get(), mark, noUA, currStatus, nl);

    if (currStatus.shouldPrint()) {
        currStatus.increaseCounter();
        const time_t currentTime = time(nullptr);
        char timeStr[60] = {};
        time2str(static_cast<int>(difftime(currentTime, startTime)), timeStr);
        auto const logStr = isIPv4 ?
                "UA2F %d has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s. There are %d empty, %lld bypass and %d fragment. Clear %lld TCP Timestamps. Mangle %lld Ipv4 ID." :
                "UA2F6 %d has handled %lld ua http, %lld tcp. Set %lld mark and %lld noUA mark in %s. There are %d empty, %lld bypass and %d fragment. Clear %lld TCP Timestamps. Mangle %lld Ipv4 ID.";
        syslog(LOG_INFO, logStr,
               currQueue, currStatus.uaCount, currStatus.tcpCount, currStatus.uaMark, currStatus.noUAMark, timeStr, currStatus.uaEmpty, currStatus.uaBypass, currStatus.uaFrag, currStatus.timestamps, currStatus.ipId);
    }

    return MNL_CB_OK;
}

static void queue_accept(const int queue_number){
    const unique_ptr<mnl_socket, function<void(mnl_socket*)>> nl {
        mnl_socket_open(NETLINK_NETFILTER),
        [](mnl_socket * const p){
            if(p != nullptr) mnl_socket_close(p);
        }
    };
    if (nl == nullptr) {
        perror("mnl_socket_open");
        syslog(LOG_ERR, "Exit at breakpoint 4.");
        exit(EXIT_FAILURE);
    }
    if (mnl_socket_bind(nl.get(), 0, MNL_SOCKET_AUTOPID) == -1) {
        perror("mnl_socket_bind");
        syslog(LOG_ERR, "Exit at breakpoint 5.");
        exit(EXIT_FAILURE);
    }
    auto const portid = mnl_socket_get_portid(nl.get());

    unique_ptr<char[]> buf {new char[sizeof_buf]};
    auto nlh = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);
    if (mnl_socket_sendto(nl.get(), nlh, nlh->nlmsg_len) == -1) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 7.");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, NFQNL_COPY_PACKET_SIZE);
    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_FLAGS,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_MASK,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));
    if (mnl_socket_sendto(nl.get(), nlh, nlh->nlmsg_len) == -1) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 8.");
        exit(EXIT_FAILURE);
    }

    int sockopt_buf = 1;
    mnl_socket_setsockopt(nl.get(), NETLINK_NO_ENOBUFS, &sockopt_buf, sizeof(int));
    syslog(LOG_NOTICE, "UA2F %d has inited successful.", queue_number);

    while (true) {
        const ssize_t recvfrom_ret = mnl_socket_recvfrom(nl.get(), buf.get(), sizeof_buf);
        if (recvfrom_ret == -1) { //stop at failure
            perror("mnl_socket_recvfrom");
            syslog(LOG_ERR, "Exit at breakpoint 9.");
            exit(EXIT_FAILURE);
        }
        const int cb_run_ret = mnl_cb_run(buf.get(), recvfrom_ret, 0, portid, queue_cb, nl.get());
        if (cb_run_ret == MNL_CB_ERROR) { //stop at failure
            perror("mnl_cb_run");
            syslog(LOG_ERR, "Exit at breakpoint 10.");
            exit(EXIT_FAILURE);
        }
    }
}

int main(const int argc, const char * const * const argv) {
    if(argc < 3){
        cout << "UA2F Usage: " << argv[0] << " queue_start_number thread_number [--ua] [--ua-bypass] [--tcp-timestamps] [--ipid] [--disable-ct-mark]" << endl;
        exit(EXIT_FAILURE);
    }
    const int queueStartNumber = atoi(argv[1]);
    const int workThreadsNum = atoi(argv[2]);
    if(queueStartNumber == 0 || workThreadsNum == 0){
        cout << "Error queue_start_number or thread_number" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "queueStartNumber is " << queueStartNumber << ". Use " << workThreadsNum << " threads." << endl;

    for(int i = 3; i < argc; ++i){
        auto const curr_arg = argv[i];
        if(strcmp(curr_arg, "--ua") == 0){
            enableMangleUa = true;
            cout << "enableMangleUa ";
        } else if(strcmp(curr_arg, "--ua-bypass") == 0){
            enableMangleUaBypass = true;
            cout << "enableMangleUaBypass ";
        } else if(strcmp(curr_arg, "--tcp-timestamps") == 0){
            enableClearTcpTimestamps = true;
            cout << "enableClearTcpTimestamps ";
        } else if(strcmp(curr_arg, "--ipid") == 0){
            enableMangleIPv4Id = true;
            cout << "enableMangleIPv4Id ";
        } else if(strcmp(curr_arg, "--disable-ct-mark") == 0){
            disableCtMark = true;
            cout << "disableCtMark ";
        }
    }
    cout << endl;

    int errCount = 0;
    while (true) {
        auto const child_status = fork();
        openlog("UA2F", LOG_CONS | LOG_PID, LOG_SYSLOG);
        if (child_status == -1) {
            syslog(LOG_ERR, "Failed to give birth.");
            syslog(LOG_ERR, "Exit at breakpoint 2.");
            exit(EXIT_FAILURE);
        } else if (child_status == 0) {
            syslog(LOG_NOTICE, "UA2F processor start at [%d].", getpid());
            break;
        } else {
            syslog(LOG_NOTICE, "Try to start UA2F processor at [%d].", child_status);
            int deadStat;
            auto const deadPid = wait(&deadStat);
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

    thread workThreads[workThreadsNum];
    for(int i = 0; i < workThreadsNum; ++i){
        workThreads[i] = thread{ queue_accept, queueStartNumber + i };
    }
    for(int i = 0; i < workThreadsNum; ++i){
        workThreads[i].join();
    }
}