升级投放目录说明
================
1) 系统升级包放入: updates/incoming/system/
2) 库文件升级包放入: updates/incoming/library/
3) 开启「自动更新」后，服务会定时扫描并安装未处理的包
4) 也可在页面点击「手动导入升级」或「立即检查」

升级包格式
--------
- .zip 内可含 manifest.json（id / description / md5 / kind）
- 系统包: files/ 下相对项目根的文件（限 backend/ rules_admin/ scripts/ index.html 等）
- 库文件包: rules/ lists/ ioc_data/ 或根目录 .json 规则文件
