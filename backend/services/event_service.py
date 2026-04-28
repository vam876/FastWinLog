#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Event loading service"""

import os
from typing import Dict, Any, Optional
from ..core.log_descriptions import get_event_description
from ..core.field_descriptions import (
    get_all_fields, get_default_visible_fields, get_field_info,
    get_recommended_fields, get_log_type, is_supported_log,
    SUPPORTED_LOG_TYPES
)
from ..repositories.sqlite_repository import SqliteRepository
from ..repositories.memory_repository import MemoryRepository
from ..repositories.evtx_repository import EvtxRepository
from ..utils.progress_tracker import ProgressTracker


class EventService:
    """事件加载服务"""
    
    # 缓存日志类型检测结果
    _log_type_cache: Dict[str, tuple] = {}
    
    def __init__(self, sqlite_repo: SqliteRepository, memory_repo: MemoryRepository,
                 evtx_repo: EvtxRepository, progress_tracker: ProgressTracker):
        self.sqlite_repo = sqlite_repo
        self.memory_repo = memory_repo
        self.evtx_repo = evtx_repo
        self.progress = progress_tracker
    
    def detect_log_type(self, file_path: str) -> tuple:
        """
        检测日志类型（通过Channel）
        Returns: (channel, log_type, is_supported)
        """
        # 检查缓存
        if file_path in self._log_type_cache:
            return self._log_type_cache[file_path]
        
        # 通过解析器检测
        channel, log_type, is_supported = self.evtx_repo.parser.detect_log_type(file_path)
        
        # 缓存结果
        self._log_type_cache[file_path] = (channel, log_type, is_supported)
        
        return channel, log_type, is_supported
    
    def load_events_paginated(self, file_path: str, page: int = 1, page_size: int = 100,
                              sort_field: str = None, sort_direction: str = 'asc') -> dict:
        """分页加载事件"""
        try:
            file_name = os.path.basename(file_path)
            
            # 通过Channel检测日志类型
            channel, log_type, is_supported = self.detect_log_type(file_path)
            
            # 策略1：尝试从SQLite缓存加载
            if self.sqlite_repo.is_cache_valid(file_path):
                print(f"[SQLite缓存] 命中缓存: {file_name}")
                result = self.sqlite_repo.load_from_cache(file_path, page, page_size, sort_field, sort_direction)
                
                if result['success']:
                    self._add_event_descriptions(result['events'])
                    result['from_cache'] = True
                    result['log_type'] = log_type
                    result['channel'] = channel
                    result['is_supported'] = is_supported
                    self._clear_progress(file_path, result['pagination']['total_count'])
                    return result
            
            # 策略2：内存缓存
            if self.memory_repo.has_cache(file_path):
                print(f"[内存缓存] 命中缓存: {file_name}")
                events, total = self.memory_repo.get_paginated(file_path, page, page_size)
                result = self._build_paginated_result(events, page, page_size, total, True)
                result['log_type'] = log_type
                result['channel'] = channel
                result['is_supported'] = is_supported
                return result
            
            # 检查并发加载
            loading_file = self.progress.get_loading_file()
            if loading_file:
                if loading_file == file_path:
                    return {'success': False, 'error': f'{file_name} 正在加载中', 'loading': True}
                else:
                    return {'success': False, 'error': f'{os.path.basename(loading_file)} 正在加载中，请等待完成', 'loading': True}
            
            # 策略3：首次加载
            self.progress.start_loading(file_path)
            events, stats = self.evtx_repo.parse_file(file_path)
            
            # 保存到内存
            self.memory_repo.set_events(file_path, events, stats)
            
            # 创建SQLite缓存
            try:
                self.sqlite_repo.create_cache(file_path, events, show_progress=True)
            except Exception as e:
                print(f"[SQLite缓存] 创建失败: {e}")
            
            # 分页返回
            total = len(events)
            start = (page - 1) * page_size
            end = start + page_size
            page_events = events[start:end]
            
            self._add_event_descriptions(page_events)
            
            result = self._build_paginated_result(page_events, page, page_size, total, False)
            result['log_type'] = log_type
            result['channel'] = channel
            result['is_supported'] = is_supported
            return result
        
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_load_progress(self, file_path: str = None) -> dict:
        """获取加载进度"""
        progress = self.progress.get_progress(file_path)
        return {'success': True, **progress}
    
    def get_available_fields(self, file_path: str, sample_size: int = 100) -> dict:
        """
        获取可用字段列表 - 通过Channel识别日志类型
        """
        try:
            # 通过Channel检测日志类型
            channel, log_type, is_supported = self.detect_log_type(file_path)

            field_dict = get_all_fields()
            sampled_fields = self._collect_available_fields(file_path, sample_size)

            # Keep recommended/default fields available even if a small sample misses them.
            sampled_fields.update(get_default_visible_fields())
            sampled_fields.update(get_recommended_fields(log_type))
            sampled_fields.update({'_event_name', '_event_description', '_event_category', '_event_severity'})

            field_info = []
            for field_name in sampled_fields:
                info = field_dict.get(field_name, {
                    'label': field_name,
                    'group': '其他',
                    'width': 140
                })
                field_info.append({
                    'name': field_name,
                    'label': info['label'],
                    'group': info['group'],
                    'width': info['width']
                })
            
            # 按分组排序
            group_order = {
                '基础信息': 0, '时间信息': 1, '事件描述': 2, '提供者信息': 3,
                '执行信息': 4, '安全信息': 5, '登录信息': 6, '网络信息': 7,
                '进程信息': 8, '服务信息': 9, 'PowerShell': 10, '远程桌面': 11,
                '对象访问': 12, '审核策略': 13, 'Kerberos': 14, '应用程序': 15,
                '远程访问': 16, '系统参数': 17, '系统信息': 18, '账户管理': 19, '文件共享': 20,
                '计划任务': 20, '错误状态': 21, '其他': 99
            }
            field_info.sort(key=lambda x: (group_order.get(x['group'], 50), x['name']))
            
            print(f"[字段列表] 日志类型: {log_type} (Channel: {channel}) | 返回 {len(field_info)} 个字段")
            
            return {
                'success': True,
                'fields': field_info,
                'default_visible': [field for field in get_default_visible_fields() if field in sampled_fields],
                'recommended': [field for field in get_recommended_fields(log_type) if field in sampled_fields],
                'log_type': log_type,
                'channel': channel,
                'is_supported': is_supported,
                'supported_types': SUPPORTED_LOG_TYPES
            }
        except Exception as e:
            print(f"[字段列表] 失败: {e}")
            return {'success': False, 'error': str(e)}

    def _collect_available_fields(self, file_path: str, sample_size: int) -> set:
        """Collect real fields from cache, memory, or a parser sample."""
        collected_fields = set()

        sample_events = []
        if self.sqlite_repo.is_cache_valid(file_path):
            result = self.sqlite_repo.load_from_cache(file_path, 1, max(1, min(sample_size, 200)))
            if result.get('success'):
                sample_events = result.get('events', [])
        elif self.memory_repo.has_cache(file_path):
            sample_events, _ = self.memory_repo.get_paginated(file_path, 1, max(1, min(sample_size, 200)))
        else:
            sample_events = self.evtx_repo.parser.parse_range(file_path, 0, max(1, min(sample_size, 200)))

        for event in sample_events:
            collected_fields.update(
                field_name for field_name, value in event.items()
                if field_name != '_error' and value not in (None, '')
            )

        return collected_fields or set(get_all_fields().keys())
    
    def _add_event_descriptions(self, events: list) -> None:
        """为事件添加描述"""
        for event in events:
            event_id = event.get('EventID')
            if event_id:
                desc = get_event_description(event_id)
                event['_event_name'] = desc['name']
                event['_event_description'] = desc['description']
                event['_event_category'] = desc['category']
                event['_event_severity'] = desc.get('severity', 'info')
    
    def _build_paginated_result(self, events: list, page: int, page_size: int, total: int, from_cache: bool) -> dict:
        """构建分页结果"""
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1
        return {
            'success': True,
            'events': events,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total_count': total,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            },
            'from_cache': from_cache
        }
    
    def _clear_progress(self, file_path: str, total: int) -> None:
        """清理进度状态"""
        self.progress.complete(file_path, total, 0)
