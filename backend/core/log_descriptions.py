#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
FastWinLog - Log Type Descriptions
Version: 1.0.0
Repository: https://github.com/vam876/FastWinLog
"""

from .windows_events_database import get_event_info as get_event_from_db

# 日志文件类型描述
LOG_FILE_DESCRIPTIONS = {
    'System': {
        'name': '系统日志',
        'description': '记录系统组件和驱动程序的事件，包括启动、关机、硬件故障等',
        'category': '系统',
        'importance': 'high'
    },
    'Application': {
        'name': '应用程序日志',
        'description': '记录应用程序事件，包括应用启动、错误、警告等',
        'category': '应用程序',
        'importance': 'high'
    },
    'Security': {
        'name': '安全日志',
        'description': '记录安全相关事件，包括登录尝试、权限更改、资源访问等',
        'category': '安全',
        'importance': 'high'
    },
    'Microsoft-Windows-PowerShell': {
        'name': 'PowerShell日志',
        'description': '记录PowerShell脚本执行、命令调用等事件',
        'category': 'PowerShell',
        'importance': 'high'
    },
    'Windows PowerShell': {
        'name': 'PowerShell日志',
        'description': '记录PowerShell脚本执行、命令调用等事件',
        'category': 'PowerShell',
        'importance': 'high'
    },
    'Microsoft-Windows-TerminalServices': {
        'name': 'TerminalServices日志',
        'description': '记录远程桌面会话、连接、重连和登录相关事件',
        'category': 'TerminalServices',
        'importance': 'high'
    },
    'Microsoft-Windows-RemoteDesktopServices': {
        'name': 'RemoteDesktop Services日志',
        'description': '记录远程桌面服务核心、会话和传输相关事件',
        'category': 'TerminalServices',
        'importance': 'high'
    },
}


def get_log_description(log_name: str) -> dict:
    """
    获取日志文件描述
    
    Args:
        log_name: 日志名称
        
    Returns:
        dict: 日志描述信息
    """
    if log_name in LOG_FILE_DESCRIPTIONS:
        return LOG_FILE_DESCRIPTIONS[log_name]
    
    for key, value in LOG_FILE_DESCRIPTIONS.items():
        if key in log_name:
            return value
    
    return {
        'name': log_name,
        'description': '未知日志类型',
        'category': '其他',
        'importance': 'low'
    }


def get_event_description(event_id: str) -> dict:
    """
    获取事件描述
    
    Args:
        event_id: 事件ID
        
    Returns:
        dict: 事件描述信息
    """
    try:
        event_info = get_event_from_db(event_id)
        if event_info['name'] != f'事件 {event_id}':
            return {
                'name': event_info['name'],
                'description': event_info['description'],
                'category': event_info['category'],
                'severity': event_info['severity'],
                'fields': event_info.get('fields', [])
            }
    except:
        pass
    
    return {
        'name': f'事件 {event_id}',
        'description': '未知事件类型',
        'category': '其他',
        'severity': 'info',
        'fields': []
    }


def get_category_color(category: str) -> str:
    """获取类别对应的颜色"""
    colors = {
        '安全': '#f44336',
        '系统': '#ff9800',
        '应用程序': '#4caf50',
        'PowerShell': '#5c6bc0',
        'TerminalServices': '#1976d2',
        '其他': '#888'
    }
    return colors.get(category, '#888')
