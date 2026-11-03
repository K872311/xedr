# Win11 干净系统基线

- `win11_baseline.json`：从干净 Win11 采集报告生成
- 匹配管线在黑白名单之前过滤：已知正常 **服务 / 计划任务 / 启动项** 不再告警
- 重新生成：

```bash
python sigma_high_priority/disable_clean_fps.py
```

或后续用管理台导入。字段：

- `services[]`: name / image_path / image_path_norm
- `tasks[]`: task_name / command / command_norm
- `startup[]`: name / command / command_norm
