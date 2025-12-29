"""
MCP Server for LogCluster Log Analysis and Anomaly Detection
基于 FastMCP 的 MCP 服务器，封装 LogCluster 日志异常检测工具
"""

import os
import json
import pandas as pd
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastmcp import FastMCP
from LogCluster import LogParser


# 初始化 FastMCP 服务器
mcp = FastMCP("LogClusterMCPServer")


def generate_statistics(df: pd.DataFrame, top_n: int = 10) -> dict:
    """生成统计信息"""
    template_counts = df['EventTemplate'].value_counts()
    total_logs = len(df)
    unique_patterns = len(template_counts)
    
    # 获取前 top_n 个模式
    top_patterns = []
    for template, count in template_counts.head(top_n).items():
        top_patterns.append({
            "template": template,
            "count": int(count),
            "percentage": round(float(count / total_logs * 100), 2)
        })
    
    # 模式分布统计
    pattern_distribution = {}
    for template, count in template_counts.items():
        pattern_distribution[template] = {
            "count": int(count),
            "percentage": round(float(count / total_logs * 100), 2)
        }
    
    return {
        "total_logs": total_logs,
        "unique_patterns": unique_patterns,
        "pattern_distribution": pattern_distribution,
        "top_patterns": top_patterns
    }


@mcp.tool()
def analyze_log_file(
    log_file_path: str,
    log_format: Optional[str] = None,
    support: Optional[int] = None,
    rsupport: Optional[float] = None,
    output_dir: Optional[str] = None,
    rex: Optional[List[str]] = None
) -> str:
    """
    分析日志文件并提取模式，使用 LogCluster 进行日志聚类和模式挖掘
    
    Args:
        log_file_path: 日志文件路径（必需）
        log_format: 日志格式，例如：<Date> <Time> <Level> <Component>: <Content>
        support: 绝对支持度阈值
        rsupport: 相对支持度阈值（百分比，0-100）
        output_dir: 输出目录，默认为日志文件所在目录
        rex: 正则表达式列表，用于过滤日志内容
    
    Returns:
        JSON 格式的分析结果和统计信息
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(log_file_path):
            return json.dumps({"error": f"日志文件不存在: {log_file_path}"}, ensure_ascii=False)
        
        # 设置默认值
        if log_format is None:
            log_format = "<Date> <Time> <Level> <Component>: <Content>"
        
        if output_dir is None:
            output_dir = os.path.dirname(log_file_path) or "."
        
        if rex is None:
            rex = []
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        # 初始化 LogParser
        parser = LogParser(
            indir=os.path.dirname(log_file_path) or ".",
            log_format=log_format,
            outdir=output_dir,
            rex=rex,
            support=support,
            rsupport=rsupport
        )
        
        # 解析日志文件
        filename = os.path.basename(log_file_path)
        parser.parse(filename)
        
        # 生成的结构化文件路径
        structured_file = os.path.join(output_dir, filename + "_structured.csv")
        
        if os.path.exists(structured_file):
            # 读取结构化数据并生成统计信息
            df = pd.read_csv(structured_file)
            stats = generate_statistics(df)
            
            return json.dumps({
                "success": True,
                "message": "日志分析完成",
                "structured_file": structured_file,
                "statistics": stats
            }, ensure_ascii=False, indent=2)
        else:
            return json.dumps({"error": "结构化文件生成失败"}, ensure_ascii=False)
    
    except Exception as e:
        return json.dumps({"error": f"分析日志文件时出错: {str(e)}"}, ensure_ascii=False)


@mcp.tool()
def detect_anomalies(
    csv_file_path: str,
    threshold: int = 3,
    max_samples: int = 5
) -> str:
    """
    检测异常日志，基于出现频率识别罕见的日志模式
    
    Args:
        csv_file_path: 结构化日志 CSV 文件路径（必需）
        threshold: 异常检测阈值，出现次数小于等于此值的视为异常（默认：3）
        max_samples: 每个异常模式返回的最大样本数（默认：5）
    
    Returns:
        JSON 格式的异常检测结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(csv_file_path):
            return json.dumps({"error": f"CSV 文件不存在: {csv_file_path}"}, ensure_ascii=False)
        
        # 读取结构化日志
        df = pd.read_csv(csv_file_path)
        
        if 'EventTemplate' not in df.columns:
            return json.dumps({"error": "CSV 文件缺少 EventTemplate 列"}, ensure_ascii=False)
        
        # 统计每个模式的出现次数
        template_counts = df['EventTemplate'].value_counts()
        
        # 找出异常模式（出现次数 <= threshold）
        anomaly_templates = template_counts[template_counts <= threshold].index.tolist()
        
        # 收集异常模式的样本
        anomalies = []
        for template in anomaly_templates:
            count = int(template_counts[template])
            # 获取样本日志
            samples = df[df['EventTemplate'] == template].head(max_samples)
            sample_logs = []
            for _, row in samples.iterrows():
                sample_logs.append({
                    "LineId": int(row.get('LineId', 0)),
                    "Content": str(row.get('Content', '')),
                    "EventId": str(row.get('EventId', ''))
                })
            
            anomalies.append({
                "template": template,
                "count": count,
                "samples": sample_logs
            })
        
        # 统计信息
        total_logs = len(df)
        anomaly_count = len(anomalies)
        normal_count = len(template_counts[template_counts > threshold])
        
        return json.dumps({
            "success": True,
            "threshold": threshold,
            "total_logs": total_logs,
            "total_patterns": len(template_counts),
            "anomaly_patterns": anomaly_count,
            "normal_patterns": normal_count,
            "anomalies": anomalies
        }, ensure_ascii=False, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"检测异常时出错: {str(e)}"}, ensure_ascii=False)


@mcp.tool()
def query_log_patterns(
    csv_file_path: str,
    event_id: Optional[str] = None,
    keyword: Optional[str] = None,
    min_occurrences: Optional[int] = None,
    limit: int = 100,
    offset: int = 0
) -> str:
    """
    查询和过滤日志模式，支持按事件ID、关键词、出现次数等条件过滤
    
    Args:
        csv_file_path: 结构化日志 CSV 文件路径（必需）
        event_id: 事件ID过滤
        keyword: 关键词搜索（在 EventTemplate 中搜索）
        min_occurrences: 最小出现次数
        limit: 返回结果数量限制（默认：100）
        offset: 结果偏移量（默认：0）
    
    Returns:
        JSON 格式的匹配日志模式列表
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(csv_file_path):
            return json.dumps({"error": f"CSV 文件不存在: {csv_file_path}"}, ensure_ascii=False)
        
        # 读取结构化日志
        df = pd.read_csv(csv_file_path)
        
        # 应用过滤条件
        filtered_df = df.copy()
        
        if event_id:
            filtered_df = filtered_df[filtered_df['EventId'] == event_id]
        
        if keyword:
            filtered_df = filtered_df[filtered_df['EventTemplate'].str.contains(keyword, na=False, case=False)]
        
        # 统计模式出现次数
        template_counts = filtered_df['EventTemplate'].value_counts()
        
        # 应用最小出现次数过滤
        if min_occurrences:
            frequent_templates = template_counts[template_counts >= min_occurrences].index
            filtered_df = filtered_df[filtered_df['EventTemplate'].isin(frequent_templates)]
            template_counts = filtered_df['EventTemplate'].value_counts()
        
        # 构建结果
        patterns = []
        for template, count in template_counts.items():
            patterns.append({
                "template": template,
                "count": int(count),
                "event_id": filtered_df[filtered_df['EventTemplate'] == template]['EventId'].iloc[0] if len(filtered_df[filtered_df['EventTemplate'] == template]) > 0 else ""
            })
        
        # 应用分页
        total = len(patterns)
        patterns = patterns[offset:offset + limit]
        
        return json.dumps({
            "success": True,
            "total": total,
            "limit": limit,
            "offset": offset,
            "patterns": patterns
        }, ensure_ascii=False, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"查询日志模式时出错: {str(e)}"}, ensure_ascii=False)


@mcp.tool()
def get_statistics(
    csv_file_path: str,
    top_n: int = 10
) -> str:
    """
    获取日志统计信息，包括总日志数、唯一模式数、模式分布等
    
    Args:
        csv_file_path: 结构化日志 CSV 文件路径（必需）
        top_n: 返回前N个最常见的模式（默认：10）
    
    Returns:
        JSON 格式的统计信息
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(csv_file_path):
            return json.dumps({"error": f"CSV 文件不存在: {csv_file_path}"}, ensure_ascii=False)
        
        # 读取结构化日志
        df = pd.read_csv(csv_file_path)
        
        # 生成统计信息
        stats = generate_statistics(df, top_n)
        
        return json.dumps({
            "success": True,
            "statistics": stats
        }, ensure_ascii=False, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"获取统计信息时出错: {str(e)}"}, ensure_ascii=False)


@mcp.tool()
def compare_log_periods(
    baseline_csv: str,
    current_csv: str,
    change_threshold: float = 50.0
) -> str:
    """
    比较两个时间段的日志差异，识别新增、减少或变化的日志模式
    
    Args:
        baseline_csv: 基准时间段的结构化日志 CSV 文件路径（必需）
        current_csv: 当前时间段的结构化日志 CSV 文件路径（必需）
        change_threshold: 变化阈值（百分比），超过此值的变化会被标记（默认：50）
    
    Returns:
        JSON 格式的日志差异信息
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(baseline_csv):
            return json.dumps({"error": f"基准 CSV 文件不存在: {baseline_csv}"}, ensure_ascii=False)
        if not os.path.exists(current_csv):
            return json.dumps({"error": f"当前 CSV 文件不存在: {current_csv}"}, ensure_ascii=False)
        
        # 读取两个文件
        baseline_df = pd.read_csv(baseline_csv)
        current_df = pd.read_csv(current_csv)
        
        # 统计模式出现次数
        baseline_counts = baseline_df['EventTemplate'].value_counts()
        current_counts = current_df['EventTemplate'].value_counts()
        
        # 获取所有模式
        all_templates = set(baseline_counts.index) | set(current_counts.index)
        
        # 比较变化
        changes = []
        new_patterns = []
        removed_patterns = []
        significant_changes = []
        
        for template in all_templates:
            baseline_count = baseline_counts.get(template, 0)
            current_count = current_counts.get(template, 0)
            
            if baseline_count == 0:
                # 新模式
                new_patterns.append({
                    "template": template,
                    "count": int(current_count)
                })
            elif current_count == 0:
                # 消失的模式
                removed_patterns.append({
                    "template": template,
                    "count": int(baseline_count)
                })
            else:
                # 计算变化百分比
                change_percent = ((current_count - baseline_count) / baseline_count) * 100
                
                changes.append({
                    "template": template,
                    "baseline_count": int(baseline_count),
                    "current_count": int(current_count),
                    "change_percent": round(float(change_percent), 2)
                })
                
                # 检查是否超过阈值
                if abs(change_percent) >= change_threshold:
                    significant_changes.append({
                        "template": template,
                        "baseline_count": int(baseline_count),
                        "current_count": int(current_count),
                        "change_percent": round(float(change_percent), 2)
                    })
        
        return json.dumps({
            "success": True,
            "baseline_total": len(baseline_df),
            "current_total": len(current_df),
            "baseline_patterns": len(baseline_counts),
            "current_patterns": len(current_counts),
            "new_patterns": new_patterns,
            "removed_patterns": removed_patterns,
            "changes": changes,
            "significant_changes": significant_changes,
            "change_threshold": change_threshold
        }, ensure_ascii=False, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"比较日志时间段时出错: {str(e)}"}, ensure_ascii=False)


@mcp.tool()
def export_patterns(
    csv_file_path: str,
    output_format: str = "json",
    output_path: Optional[str] = None,
    include_samples: bool = False
) -> str:
    """
    导出日志模式到 JSON 或 TXT 文件
    
    Args:
        csv_file_path: 结构化日志 CSV 文件路径（必需）
        output_format: 输出格式：json 或 txt（默认：json）
        output_path: 输出文件路径，如果不指定则自动生成
        include_samples: 是否包含样本日志（默认：false）
    
    Returns:
        JSON 格式的导出结果信息
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(csv_file_path):
            return json.dumps({"error": f"CSV 文件不存在: {csv_file_path}"}, ensure_ascii=False)
        
        # 读取结构化日志
        df = pd.read_csv(csv_file_path)
        
        # 统计模式
        template_counts = df['EventTemplate'].value_counts()
        
        # 构建导出数据
        export_data = {
            "total_logs": len(df),
            "unique_patterns": len(template_counts),
            "patterns": []
        }
        
        for template, count in template_counts.items():
            pattern_data = {
                "template": template,
                "count": int(count),
                "event_id": df[df['EventTemplate'] == template]['EventId'].iloc[0] if len(df[df['EventTemplate'] == template]) > 0 else ""
            }
            
            if include_samples:
                samples = df[df['EventTemplate'] == template].head(5)
                pattern_data["samples"] = [
                    {
                        "LineId": int(row.get('LineId', 0)),
                        "Content": str(row.get('Content', ''))
                    }
                    for _, row in samples.iterrows()
                ]
            
            export_data["patterns"].append(pattern_data)
        
        # 确定输出路径
        if output_path is None:
            base_path = os.path.splitext(csv_file_path)[0]
            output_path = f"{base_path}_patterns.{output_format}"
        
        # 导出文件
        if output_format == "json":
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
        elif output_format == "txt":
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"Total Logs: {export_data['total_logs']}\n")
                f.write(f"Unique Patterns: {export_data['unique_patterns']}\n\n")
                for pattern in export_data["patterns"]:
                    f.write(f"Pattern: {pattern['template']}\n")
                    f.write(f"Count: {pattern['count']}\n")
                    f.write(f"Event ID: {pattern['event_id']}\n")
                    if include_samples and 'samples' in pattern:
                        f.write("Samples:\n")
                        for sample in pattern['samples']:
                            f.write(f"  - {sample['Content']}\n")
                    f.write("\n")
        else:
            return json.dumps({"error": f"不支持的输出格式: {output_format}"}, ensure_ascii=False)
        
        return json.dumps({
            "success": True,
            "message": "模式导出成功",
            "output_path": output_path,
            "format": output_format
        }, ensure_ascii=False, indent=2)
    
    except Exception as e:
        return json.dumps({"error": f"导出模式时出错: {str(e)}"}, ensure_ascii=False)


# FastMCP 使用 SSE 传输启动服务器
if __name__ == "__main__":
    # 使用 SSE (Server-Sent Events) 传输，监听 127.0.0.1:4001
    mcp.run(transport="sse", host="127.0.0.1", port=4001)
