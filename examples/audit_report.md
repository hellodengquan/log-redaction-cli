# 日志脱敏审计报告

- **处理时间**: 2026-06-15 11:43:39
- **源文件**: `/Users/dengquan/Downloads/job/code-annotation/dogfeeding/solo/code/173-log-redaction-cli/examples/sample.log`
- **输出文件**: `/Users/dengquan/Downloads/job/code-annotation/dogfeeding/solo/code/173-log-redaction-cli/examples/audit_report.md`

## 统计概览

- **脱敏总条数**: 10

### 按敏感类型统计

| 类型 | 数量 |
| --- | --- |
| email | 5 |
| phone | 5 |

### 按规则统计

| 规则名称 | 数量 |
| --- | --- |
| china-mobile-phone | 5 |
| email-address | 5 |

## 详细记录

| 行号 | 类型 | 规则 | 原始值 | 脱敏值 | 位置 |
| --- | --- | --- | --- | --- | --- |
| 1 | phone | china-mobile-phone | `13812345678` | `138****5678` | [65-76] |
| 2 | phone | china-mobile-phone | `139-9876-5432` | `139****5432` | [54-67] |
| 3 | email | email-address | `support@example.com` | `s******@example.com` | [51-70] |
| 4 | email | email-address | `zhangsan.2024@company.org` | `z************@company.org` | [51-76] |
| 5 | phone | china-mobile-phone | `+86 156 0000 1111` | `156****1111` | [55-72] |
| 6 | phone | china-mobile-phone | `13711112222` | `137****2222` | [51-62] |
| 6 | email | email-address | `test_user123@mail.test.io` | `t***********@mail.test.io` | [69-94] |
| 7 | email | email-address | `admin@internal.cn` | `a****@internal.cn` | [45-62] |
| 9 | phone | china-mobile-phone | `18866669999` | `188****9999` | [52-63] |
| 10 | email | email-address | `a.b+c@domain.co.uk` | `a****@domain.co.uk` | [53-71] |
