#ifndef BINDING_H_INCLUDED
#define BINDING_H_INCLUDED

#include <toml.hpp>

#include "handler/settings.h"
#include "crontask.h"
#include "proxygroup.h"
#include "regmatch.h"
#include "ruleset.h"

namespace toml
{
    template<>
    struct from<ProxyGroupConfig>
    {
        static ProxyGroupConfig from_toml(const value& v)
        {
            ProxyGroupConfig conf;
            conf.Name = find<String>(v, "name");
            String type = find<String>(v, "type");
            String strategy = find_or<String>(v, "strategy", "");
            switch(hash_(type))
            {
            case "select"_hash:
                conf.Type = ProxyGroupType::Select;
                break;
            case "url-test"_hash:
                conf.Type = ProxyGroupType::URLTest;
                conf.Url = find<String>(v, "url");
                conf.Interval = find<Integer>(v, "interval");
                conf.Tolerance = find_or<Integer>(v, "tolerance", 0);
                if(v.contains("lazy"))
                    conf.Lazy = find_or<bool>(v, "lazy", false);
                if(v.contains("evaluate-before-use"))
                    conf.EvaluateBeforeUse = find_or(v, "evaluate-before-use", conf.EvaluateBeforeUse.get());
                break;
            case "load-balance"_hash:
                conf.Type = ProxyGroupType::LoadBalance;
                conf.Url = find<String>(v, "url");
                conf.Interval = find<Integer>(v, "interval");
                switch(hash_(strategy))
                {
                case "consistent-hashing"_hash:
                    conf.Strategy = BalanceStrategy::ConsistentHashing;
                    break;
                case "round-robin"_hash:
                    conf.Strategy = BalanceStrategy::RoundRobin;
                    break;
                }
                if(v.contains("persistent"))
                    conf.Persistent = find_or(v, "persistent", conf.Persistent.get());
                break;
            case "fallback"_hash:
                conf.Type = ProxyGroupType::Fallback;
                conf.Url = find<String>(v, "url");
                conf.Interval = find<Integer>(v, "interval");
                if(v.contains("evaluate-before-use"))
                    conf.EvaluateBeforeUse = find_or(v, "evaluate-before-use", conf.EvaluateBeforeUse.get());
                break;
            case "relay"_hash:
                conf.Type = ProxyGroupType::Relay;
                break;
            case "ssid"_hash:
                conf.Type = ProxyGroupType::SSID;
                break;
            case "smart"_hash:
                conf.Type = ProxyGroupType::Smart;
                conf.Url = find<String>(v, "url");
                conf.Interval = find<Integer>(v, "interval");
                conf.Tolerance = find_or<Integer>(v, "tolerance", 0);
                if(v.contains("lazy"))
                    conf.Lazy = find_or<bool>(v, "lazy", false);
                if(v.contains("evaluate-before-use"))
                    conf.EvaluateBeforeUse = find_or(v, "evaluate-before-use", conf.EvaluateBeforeUse.get());
                if(v.contains("uselightgbm"))
                    conf.UseLightGBM = find_or<bool>(v, "uselightgbm", false);
                if(v.contains("collectdata"))
                    conf.CollectData = find_or<bool>(v, "collectdata", false);
                if(v.contains("policy-priority"))
                    conf.PolicyPriority = find_or<StrArray>(v, "policy-priority", {});
                if(v.contains("filter"))
                    conf.Filter = find_or<String>(v, "filter", "");
                if(v.contains("include-all"))
                    conf.IncludeAll = find_or<bool>(v, "include-all", false);
                break;
            default:
                throw serialization_error(format_error("Proxy Group has unsupported type!", v.at("type").location(), "should be one of following: select, url-test, load-balance, fallback, relay, ssid"), v.at("type").location());
            }
            conf.Timeout = find_or(v, "timeout", 5);
            conf.Proxies = find_or<StrArray>(v, "rule", {});
            conf.UsingProvider = find_or<StrArray>(v, "use", {});
            if(conf.Proxies.empty() && conf.UsingProvider.empty())
                throw serialization_error(format_error("Proxy Group must contains at least one of proxy match rule or provider!", v.location(), "here"), v.location());
            if(v.contains("disable-udp"))
                conf.DisableUdp = find_or(v, "disable-udp", conf.DisableUdp.get());
            return conf;
        }
    };

    template<>
    struct from<RulesetConfig>
    {
        static RulesetConfig from_toml(const value& v)
        {
            RulesetConfig conf;
            conf.Group = find<String>(v, "group");
            String type = find_or<String>(v, "type", "surge-ruleset");
            switch(hash_(type))
            {
            /*
            case "surge-ruleset"_hash:
                conf.Type = RulesetType::SurgeRuleset;
                conf.Url = "surge:";
                break;
            case "quantumultx"_hash:
                conf.Type = RulesetType::QuantumultX;
                conf.Url = "quanx:";
                break;
            case "clash-domain"_hash:
                conf.Type = RulesetType::ClashDomain;
                conf.Url = type;
                break;
            case "clash-ipcidr"_hash:
                conf.Type = RulesetType::ClashIpCidr;
                conf.Url = type;
                break;
            case "clash-classic"_hash:
                conf.Type = RulesetType::ClashClassic;
                conf.Url = type;
                break;
            */
            case "surge-ruleset"_hash:
                conf.Url = "surge:";
                break;
            case "quantumultx"_hash:
                conf.Url = "quanx:";
                break;
            case "clash-domain"_hash:
            case "clash-ipcidr"_hash:
            case "clash-classic"_hash:
                conf.Url = type + ":";
                break;
            default:
                throw serialization_error(format_error("Ruleset has unsupported type!", v.at("type").location(), "should be one of following: surge-ruleset, quantumultx, clash-domain, clash-ipcidr, clash-classic"), v.at("type").location());
            }
            conf.Url += find<String>(v, "ruleset");
            conf.Interval = find_or<Integer>(v, "interval", 86400);
            return conf;
        }
    };

    template<>
    struct from<RegexMatchConfig>
    {
        static RegexMatchConfig from_toml(const value& v)
        {
            RegexMatchConfig conf;
            if(v.contains("script"))
            {
                conf.Script = find<String>(v, "script");
                return conf;
            }
            conf.Match = find<String>(v, "match");
            if(v.contains("emoji"))
                conf.Replace = find<String>(v, "emoji");
            else
                conf.Replace = find<String>(v, "replace");
            return conf;
        }
    };

    template<>
    struct from<CronTaskConfig>
    {
        static CronTaskConfig from_toml(const value& v)
        {
            CronTaskConfig conf;
            conf.Name = find<String>(v, "name");
            conf.CronExp = find<String>(v, "cronexp");
            conf.Path = find<String>(v, "path");
            conf.Timeout = find_or<Integer>(v, "timeout", 0);
            return conf;
        }
    };

    template<>
    struct from<tribool>
    {
        static tribool from_toml(const value& v)
        {
            tribool t;
            t.set(v.as_boolean());
            return t;
        }
    };
}

namespace INIBinding
{
    template<class T> struct from
    {};

    // 工具函数：将 vector<string_view> 转为 vector<string>
    template<typename T>
    std::vector<std::string> to_string_vector(const std::vector<T>& v) {
        std::vector<std::string> result;
        result.reserve(v.size());
        for (const auto& s : v) result.emplace_back(s);
        return result;
    }

    template<>
    struct from<ProxyGroupConfig>
    {
        static ProxyGroupConfigs from_ini(const StrArray &arr)
        {
            // 打印原始 ini 配置内容，便于调试
            std::string ini_raw;
            for (const auto& line : arr) ini_raw += line + "\n";
            writeLog(LOG_TYPE_INFO, "custom_proxy_group ini原始内容:\n" + ini_raw, LOG_LEVEL_INFO);

            ProxyGroupConfigs confs;
            for(const String &x : arr)
            {
                StrArray vArray = split(x, "`");
                if(vArray.size() < 3)
                    continue;

                ProxyGroupConfig conf;
                conf.Name = vArray[0];
                String type = vArray[1];

                // 识别类型
                switch(hash_(type))
                {
                    case "select"_hash:       conf.Type = ProxyGroupType::Select; break;
                    case "relay"_hash:        conf.Type = ProxyGroupType::Relay; break;
                    case "url-test"_hash:     conf.Type = ProxyGroupType::URLTest; break;
                    case "fallback"_hash:     conf.Type = ProxyGroupType::Fallback; break;
                    case "load-balance"_hash: conf.Type = ProxyGroupType::LoadBalance; break;
                    case "ssid"_hash:         conf.Type = ProxyGroupType::SSID; break;
                    case "smart"_hash:        conf.Type = ProxyGroupType::Smart; break;
                    default: continue;
                }

                unsigned int rules_upper_bound = vArray.size();
                if(conf.Type == ProxyGroupType::URLTest || conf.Type == ProxyGroupType::LoadBalance || conf.Type == ProxyGroupType::Fallback)
                {
                    if(rules_upper_bound < 5) continue;
                    rules_upper_bound -= 2;
                    conf.Url = vArray[rules_upper_bound];
                    parseGroupTimes(vArray[rules_upper_bound + 1], &conf.Interval, &conf.Timeout, &conf.Tolerance);
                }

                // smart组特殊处理
                if (conf.Type == ProxyGroupType::Smart) {
                    // 取最后两个非空字段
                    std::vector<std::string> nonEmptyFields;
                    for (auto it = vArray.rbegin(); it != vArray.rend(); ++it) {
                        if (!it->empty()) nonEmptyFields.push_back(*it);
                        if (nonEmptyFields.size() == 2) break;
                    }
                    std::string timePart, params;
                    if (nonEmptyFields.size() == 2) {
                        // 最后一个非空字段为 smart参数，倒数第二个为时间参数
                        params = nonEmptyFields[0];
                        timePart = nonEmptyFields[1];
                    } else if (nonEmptyFields.size() == 1) {
                        // 只有一个非空字段，可能只有时间参数
                        timePart = nonEmptyFields[0];
                    }
                    // 先解析时间参数
                    parseGroupTimes(timePart, &conf.Interval, &conf.Timeout, &conf.Tolerance);
                    // 再解析 smart 参数
                    if (!params.empty() && params.find(":") != std::string::npos) {
                        StrArray paramList = split(params, ",");
                        for (size_t i = 0; i < paramList.size(); ++i) {
                            // 新增：打印每个参数原始内容
                            writeLog(LOG_TYPE_INFO, "smart参数分割: paramList[" + std::to_string(i) + "]=" + paramList[i], LOG_LEVEL_INFO);
                            auto pos = paramList[i].find(':');
                            if (pos == std::string::npos) continue;
                            std::string key = trim(paramList[i].substr(0, pos));
                            std::string value = trim(paramList[i].substr(pos + 1));
                            // 新增：打印 key 内容
                            writeLog(LOG_TYPE_INFO, "smart参数key: '" + key + "'", LOG_LEVEL_INFO);
                            if (key == "policy-priority") {
                                // 如果 value 以 [ 开头但不以 ] 结尾，说明被截断了
                                while (!value.empty() && value.front() == '[' && (value.back() != ']') && i + 1 < paramList.size()) {
                                    value += "," + paramList[++i];
                                }
                                // 调试日志：原始 value
                                writeLog(LOG_TYPE_INFO, "policy-priority 解析: raw=" + value, LOG_LEVEL_INFO);
                                // 去除中括号
                                if (!value.empty() && value.front() == '[' && value.back() == ']') {
                                    value = value.substr(1, value.size() - 2);
                                }
                                // 支持逗号或分号分隔
                                StrArray arr;
                                if (value.find(';') != std::string::npos) {
                                    arr = split(value, ";");
                                } else {
                                    arr = split(value, ",");
                                }
                                conf.PolicyPriority.clear();
                                for (auto& v : arr) {
                                    std::string before = v;
                                    v = trim(v);
                                    // 去除首尾引号
                                    if (!v.empty() && (v.front() == '"' || v.front() == '\'')) v = v.substr(1);
                                    if (!v.empty() && (v.back() == '"' || v.back() == '\'')) v.pop_back();
                                    // 调试日志：每个元素处理前后
                                    writeLog(LOG_TYPE_INFO, "policy-priority 元素: before='" + before + "', after='" + v + "'", LOG_LEVEL_INFO);
                                    if (!v.empty()) conf.PolicyPriority.push_back(v);
                                }
                                // 调试日志：最终结果
                                writeLog(LOG_TYPE_INFO, "policy-priority 结果: " + join(conf.PolicyPriority, ","), LOG_LEVEL_INFO);
                            } else if (key == "uselightgbm") conf.UseLightGBM = (value == "true");
                            else if (key == "collectdata") conf.CollectData = (value == "true");
                        }
                    }
                    // 处理 proxies/provider（去掉最后两个字段）
                    for(unsigned int i = 2; i < vArray.size() - 2; i++)
                    {
                        if(startsWith(vArray[i], "!!PROVIDER="))
                        {
                            string_array list = split(vArray[i].substr(11), ",");
                            conf.UsingProvider.reserve(conf.UsingProvider.size() + list.size());
                            std::move(list.begin(), list.end(), std::back_inserter(conf.UsingProvider));
                        }
                        else
                            conf.Proxies.emplace_back(std::move(vArray[i]));
                    }
                } else {
                    // 其它组类型
                    for(unsigned int i = 2; i < rules_upper_bound; i++)
                    {
                        if(startsWith(vArray[i], "!!PROVIDER="))
                        {
                            string_array list = split(vArray[i].substr(11), ",");
                            conf.UsingProvider.reserve(conf.UsingProvider.size() + list.size());
                            std::move(list.begin(), list.end(), std::back_inserter(conf.UsingProvider));
                        }
                        else
                            conf.Proxies.emplace_back(std::move(vArray[i]));
                    }
                }

                // 日志输出
                writeLog(LOG_TYPE_INFO, "custom_proxy_group 解析: name=" + conf.Name +
                    ", type=" + std::to_string((int)conf.Type) +
                    ", UseLightGBM=" + (conf.UseLightGBM.is_undef() ? "undef" : (conf.UseLightGBM.get() ? "true" : "false")) +
                    ", CollectData=" + (conf.CollectData.is_undef() ? "undef" : (conf.CollectData.get() ? "true" : "false")) +
                    ", PolicyPriority=" + join(conf.PolicyPriority, ",") +
                    ", Filter=" + conf.Filter, LOG_LEVEL_INFO);

                confs.emplace_back(std::move(conf));
            }
            return confs;
        }
    };

    template<>
    struct from<RulesetConfig>
    {
        static RulesetConfigs from_ini(const StrArray &arr)
        {
            /*
            static const std::map<std::string, RulesetType> RulesetTypes = {
                {"clash-domain:", RulesetType::ClashDomain},
                {"clash-ipcidr:", RulesetType::ClashIpCidr},
                {"clash-classic:", RulesetType::ClashClassic},
                {"quanx:", RulesetType::QuantumultX},
                {"surge:", RulesetType::SurgeRuleset}
            };
            */
            RulesetConfigs confs;
            for(const String &x : arr)
            {
                RulesetConfig conf;
                String::size_type pos = x.find(",");
                if(pos == String::npos)
                    continue;
                conf.Group = x.substr(0, pos);
                if(x.substr(pos + 1, 2) == "[]")
                {
                    conf.Url = x.substr(pos + 1);
                    //conf.Type = RulesetType::SurgeRuleset;
                    confs.emplace_back(std::move(conf));
                    continue;
                }
                String::size_type epos = x.rfind(",");
                if(pos != epos)
                {
                    conf.Interval = to_int(x.substr(epos + 1), 0);
                    conf.Url = x.substr(pos + 1, epos - pos - 1);
                }
                else
                    conf.Url = x.substr(pos + 1);
                confs.emplace_back(std::move(conf));
            }
            return confs;
        }
    };

    template<>
    struct from<CronTaskConfig>
    {
        static CronTaskConfigs from_ini(const StrArray &arr)
        {
            CronTaskConfigs confs;
            for(const String &x : arr)
            {
                CronTaskConfig conf;
                StrArray vArray = split(x, "`");
                if(vArray.size() < 3)
                    continue;
                conf.Name = vArray[0];
                conf.CronExp = vArray[1];
                conf.Path = vArray[2];
                if(vArray.size() > 3)
                    conf.Timeout = to_int(vArray[3], 0);
                confs.emplace_back(std::move(conf));
            }
            return confs;
        }
    };

    template<>
    struct from<RegexMatchConfig>
    {
        static RegexMatchConfigs from_ini(const StrArray &arr, const std::string &delimiter)
        {
            RegexMatchConfigs confs;
            for(const String &x : arr)
            {
                RegexMatchConfig conf;
                if(startsWith(x, "script:"))
                {
                    conf.Script = x.substr(7);
                    confs.emplace_back(std::move(conf));
                    continue;
                }
                String::size_type pos = x.rfind(delimiter);
                conf.Match = x.substr(0, pos);
                if(pos != String::npos && pos < x.size() - 1)
                    conf.Replace = x.substr(pos + 1);
                confs.emplace_back(std::move(conf));
            }
            return confs;
        }
    };
}

#endif // BINDING_H_INCLUDED
