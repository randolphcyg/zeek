# SCRIPT_ID: DETECT_ATT_TENDA_AC15_v1
# NoticeTypes: Tenda_Exploit::CVE_2018_5767_Exploit
# RuleVersion: 1.0.0
# DetectionPack: iot_firmware
# PackVersion: 2.0.0
# Severity: critical
# Confidence: 0.90
# Protocols: http
# ATT&CK: T1190
# RequiredLogs: http
# FalsePositives: 针对该接口的授权漏洞验证流量会命中。

# 恶意行为检测脚本配置
# 行为类型：Tenda AC15路由器Cookie缓冲区溢出漏洞利用(CVE-2018-5767)
# 行为分类：Web攻击/缓冲区溢出
# 行为描述：检测HTTP Cookie头部中异常超长的password字段，针对/goform/get_online_list接口

@load base/protocols/http
@load base/frameworks/notice

module Tenda_Exploit;

export {
    # 定义一个新的告警类型
    redef enum Notice::Type += {
        CVE_2018_5767_Exploit
    };

    # 定义阈值：正常密码通常不会超过 64 字符，设定 200 为警戒线
    # 攻击 Payload 通常远大于此长度以覆盖返回地址
    const PASSWORD_LENGTH_THRESHOLD: count = 200 &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    # 1. 只检测客户端发出的请求头 (is_orig=T)
    if ( ! is_orig ) return;

    # 2. 检查是否为 Cookie 头 (Zeek 自动转大写)
    if ( name == "COOKIE" )
        {
        # 3. 检查是否包含目标参数 "password="
        if ( "password=" in value )
            {
            # 4. 提取 Cookie 值的长度
            # 注意：这里计算的是整个 Cookie 值的长度，包含其他字段。
            # 但在利用场景中，password 字段通常占据绝大部分长度。
            local payload_len = |value|;

            if ( payload_len > PASSWORD_LENGTH_THRESHOLD )
                {
                # 5. 进一步确认 URI 是否为漏洞接口 /goform/get_online_list
                if ( c?$http && c$http?$uri && "/goform/get_online_list" in c$http$uri )
                    {
                    # 触发告警
                    NOTICE([$note=CVE_2018_5767_Exploit,
                            $msg=fmt("Detected Tenda Router Cookie Overflow Attack (CVE-2018-5767)! Payload Length: %d", payload_len),
                            $sub=fmt("Payload Snippet: %s...", sub_bytes(value, 0, 50)),
                            $conn=c,
                            $identifier=cat(c$id$orig_h, c$id$resp_h, c$http$uri)]);
                    }
                }
            }
        }
    }
