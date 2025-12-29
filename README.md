# LogCluster

代码github地址：https://github.com/logpai/logparser

[LogCluster](http://ristov.github.io/logcluster/) is a Perl-based tool for log file clustering and mining line patterns from log files. The development of LogCluster was inspired by [SLCT](http://ristov.github.io/slct/), but LogCluster includes a number of novel features and data processing options.

To provide a common interface for log parsing, we write a Python wrapper around the original [LogCluster source code in Perl](https://github.com/ristov/logcluster) (released under GPL license). This also eases our benchmarking experiments. The implementation has been tested on both Linux and Windows systems. Especially, [Strawberry Perl](http://strawberryperl.com/) was installed to run the Perl program on Windows.

Read more information about LogCluster from the following paper:

+ Risto Vaarandi, Mauno Pihelgas. [LogCluster - A Data Clustering and Pattern Mining Algorithm for Event Logs](http://ristov.github.io/publications/cnsm15-logcluster-web.pdf), *Proceedings of the 11th International Conference on Network and Service Management (CNSM)*, 2015.


## **LogCluster MCP 服务器使用说明**

MCP工具作者：庞力铖

github地址：https://github.com/Plc912/LogCluster-master.git

邮箱：3522236586@qq.com

## 安装依赖

```bash
pip install -r requirements.txt
```

## 启动服务器

### 方式 1: 使用 fastmcp 命令（推荐）

```bash
fastmcp run
```

这将自动读取 `fastmcp.json` 配置文件，在 `http://127.0.0.1:4001` 启动服务器，使用 SSE 传输。

### 方式 2: 直接运行 Python 文件

```bash
python mcp_logcluster_server.py
```

这将使用代码中指定的 SSE 传输配置，在 `http://127.0.0.1:4001` 启动服务器。

### 方式 3: 使用 fastmcp 命令指定参数

```bash
fastmcp run mcp_logcluster_server.py --transport sse --host 127.0.0.1 --port 4001
```

服务器将在 `http://127.0.0.1:4001` 启动，使用 SSE (Server-Sent Events) 传输协议。

**注意**: 所有方式都使用 SSE 传输，而不是 STDIO。SSE 端点通常位于 `http://127.0.0.1:4001/sse`。

## 可用工具

### 1. analyze_log_file

分析日志文件并提取模式

**参数：**

- `log_file_path` (必需): 日志文件路径
- `log_format` (可选): 日志格式，例如：`<Date> <Time> <Level> <Component>: <Content>`
- `support` (可选): 绝对支持度阈值
- `rsupport` (可选): 相对支持度阈值（百分比，0-100）
- `output_dir` (可选): 输出目录，默认为日志文件所在目录
- `rex` (可选): 正则表达式列表，用于过滤日志内容

**返回：** 包含分析结果和统计信息的 JSON

### 2. detect_anomalies

检测异常日志，基于出现频率识别罕见的日志模式

**参数：**

- `csv_file_path` (必需): 结构化日志 CSV 文件路径
- `threshold` (可选，默认3): 异常检测阈值，出现次数小于等于此值的视为异常
- `max_samples` (可选，默认5): 每个异常模式返回的最大样本数

**返回：** 包含异常模式列表、样本日志和统计信息的 JSON

### 3. query_log_patterns

查询和过滤日志模式

**参数：**

- `csv_file_path` (必需): 结构化日志 CSV 文件路径
- `event_id` (可选): 事件ID过滤
- `keyword` (可选): 关键词搜索（在 EventTemplate 中搜索）
- `min_occurrences` (可选): 最小出现次数
- `limit` (可选，默认100): 返回结果数量限制
- `offset` (可选，默认0): 结果偏移量

**返回：** 匹配的日志模式列表

### 4. get_statistics

获取日志统计信息

**参数：**

- `csv_file_path` (必需): 结构化日志 CSV 文件路径
- `top_n` (可选，默认10): 返回前N个最常见的模式

**返回：** 包含总日志数、唯一模式数、模式分布等的统计信息

### 5. compare_log_periods

比较两个时间段的日志差异

**参数：**

- `baseline_csv` (必需): 基准时间段的结构化日志 CSV 文件路径
- `current_csv` (必需): 当前时间段的结构化日志 CSV 文件路径
- `change_threshold` (可选，默认50): 变化阈值（百分比），超过此值的变化会被标记

**返回：** 包含新增、减少或变化的日志模式信息

### 6. export_patterns

导出日志模式到 JSON 或 TXT 文件

**参数：**

- `csv_file_path` (必需): 结构化日志 CSV 文件路径
- `output_format` (可选，默认json): 输出格式：json 或 txt
- `output_path` (可选): 输出文件路径，如果不指定则自动生成
- `include_samples` (可选，默认false): 是否包含样本日志

**返回：** 导出结果信息

## 测试数据

项目包含以下测试数据：

- `OpenSSH_2k.log` - 原始日志文件
- `OpenSSH_2k.log_structured.csv` - 已处理的结构化日志
- `BGL_2k.log_structured.csv` - BGL 日志的结构化数据

## 使用示例

### 分析日志文件

```python
{
  "log_file_path": "E:\\software\\MCP__Proj\\log\\logcluster-master\\OpenSSH_2k.log",
  "log_format": "<Date> <Time> <Level> <Component>: <Content>",
  "rsupport": 0.1
}
```

### 检测异常

```python
{
  "csv_file_path": "E:\\software\\MCP__Proj\\log\\logcluster-master\\OpenSSH_2k.log_structured.csv",
  "threshold": 3,
  "max_samples": 5
}
```

### 获取统计信息

```python
{
  "csv_file_path": "E:\\software\\MCP__Proj\\log\\logcluster-master\\OpenSSH_2k.log_structured.csv",
  "top_n": 10
}
```

## 注意事项

1. **Perl 环境**：LogCluster 的核心代码是用 Perl 编写的，需要安装 Perl 解释器。在 Windows 上，推荐使用 [Strawberry Perl](http://strawberryperl.com/)。
2. **文件路径**：确保所有文件路径都是有效的，并且有读取/写入权限。
3. **日志格式**：如果日志格式不标准，可能需要调整 `log_format` 参数以匹配实际的日志格式。
4. **性能**：对于大型日志文件，处理可能需要一些时间。建议先在小样本上测试。
