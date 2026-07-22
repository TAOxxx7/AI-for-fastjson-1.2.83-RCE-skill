# fastjson-jsontype-rce-skill

AI Agent Skill: **Fastjson 1.2.66-1.2.83 @JSONType RCE (QVD-2026-43021)**

自包含 skill — 所有利用代码内嵌，不依赖第三方 GitHub 仓库。
唯一外部依赖是 Maven Central 的 `org.ow2.asm`（Java 标准字节码库，Spring 等框架依赖，不会消失）。

---

## 快速导入

将 `SKILL.md` 放入 AI 智能体的技能目录即可。对智能体说：

> 检测 http://TARGET:8080/api/parse 是否有 Fastjson @JSONType 漏洞

---

## 自包含设计

| 需要什么 | 来源 | 可靠性 |
|---------|------|--------|
| PayloadKit.java | **SKILL.md 内嵌完整源码** | 永久存在 |
| dispatch.py | **SKILL.md 内嵌完整源码** | 永久存在 |
| ASM jar | Maven Central (`org.ow2.asm`) | Spring/Hibernate 间接依赖，不会消失 |
| JDK + Python 3 | 系统自带 | 长期稳定 |

不依赖任何第三方 GitHub 仓库。

---

## 技能能力

智能体加载此 skill 后能独立完成：

1. **指纹识别** — DNSLog / 报错特征判断 Fastjson 版本
2. **SafeMode 检测** — 确认目标是否免疫
3. **ClassLoader 判断** — 区分 FatJar vs WAR 部署
4. **Payload 生成** — JDK 8 单次 / JDK 17/21 fd 枚举
5. **OOB 回显** — HTTP 反连 / DNSLog / 反弹 Shell
6. **批量验证** — 循环 + 结果收集

---

## 许可

仅供安全研究和授权渗透测试使用。
