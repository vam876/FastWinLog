#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
FastWinLog - Main API
Version: 1.0.0
Repository: https://github.com/vam876/FastWinLog
"""

import os
import sys
from typing import Dict, Any, List, Optional

# webview延迟导入，避免测试时的路径问题
webview = None
def _get_webview():
    global webview
    if webview is None:
        import webview as wv
        webview = wv
    return webview

# 服务层
from ..services.log_service import LogService
from ..services.event_service import EventService
from ..services.search_service import SearchService
from ..services.alert_service import AlertService
from ..services.cache_service import CacheService
from ..services.statistics_service import StatisticsService

# 仓储层
from ..repositories.sqlite_repository import SqliteRepository
from ..repositories.memory_repository import MemoryRepository
from ..repositories.evtx_repository import EvtxRepository

# 工具类
from ..utils.progress_tracker import ProgressTracker
from ..utils.memory_manager import MemoryManager

# Core modules
from ..core.alert_store import AlertStore
from ..core.log_descriptions import get_event_description
from ..core.security_presets import (
    get_all_presets, get_presets_by_category, get_preset_by_id,
    PRESET_CATEGORIES, SEVERITY_LEVELS, OPERATORS, build_sql_condition
)
from ..core.field_descriptions import (
    get_log_type, is_supported_log, SUPPORTED_LOG_TYPES,
    get_recommended_fields, get_default_visible_fields, get_all_fields
)


class LogAnalysisApi:
    """Log Analysis API"""
    
    def __init__(self):
        """初始化API"""
        # 获取基础目录
        if getattr(sys, 'frozen', False):
            self.base_dir = os.path.dirname(sys.executable)
        else:
            self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        self.logs_dir = os.path.join(self.base_dir, 'logs')
        
        # 初始化工具类
        self.progress_tracker = ProgressTracker()
        self.memory_manager = MemoryManager()
        
        # 初始化仓储层
        self.sqlite_repo = SqliteRepository('cache')
        self.memory_repo = MemoryRepository(self.memory_manager)
        self.evtx_repo = EvtxRepository(self.base_dir, self.progress_tracker)
        
        # Initialize core modules
        self.alert_store = AlertStore(self.sqlite_repo.cache_dir)
        
        # 初始化服务层
        self.log_service = LogService(self.base_dir, self.sqlite_repo, self.memory_manager)
        self.event_service = EventService(self.sqlite_repo, self.memory_repo, self.evtx_repo, self.progress_tracker)
        self.search_service = SearchService(self.sqlite_repo, self.memory_repo, self.evtx_repo)
        self.alert_service = AlertService(self.alert_store, self.sqlite_repo, self.logs_dir)
        self.cache_service = CacheService(self.sqlite_repo, self.memory_manager)
        self.statistics_service = StatisticsService(self.sqlite_repo)
        
        print("[API] Initialized")

    def _update_logs_directory(self, logs_dir: str) -> str:
        """Update the active logs directory across components."""
        normalized_dir = os.path.abspath(logs_dir or os.path.join(self.base_dir, 'logs'))
        self.logs_dir = normalized_dir
        self.log_service.set_logs_dir(normalized_dir)
        self.alert_service.logs_dir = normalized_dir
        self.evtx_repo.logs_dir = normalized_dir
        return normalized_dir

    # ================= 日志文件API =================
    
    def get_log_files(self, include_loaded: bool = True) -> dict:
        """获取日志文件列表"""
        print(f"[API] get_log_files 被调用, include_loaded={include_loaded}")
        result = self.log_service.get_log_files(include_loaded)
        print(f"[API] get_log_files 返回 {result.get('total', 0)} 个文件")
        return result
    
    def get_file_info(self, file_path: str) -> dict:
        """获取文件详细信息"""
        return self.log_service.get_file_info(file_path)

    def get_current_log_directory(self) -> dict:
        """获取当前日志目录"""
        return {
            'success': True,
            'logs_dir': self.logs_dir
        }
    
    def select_log_file(self) -> dict:
        """打开文件选择对话框"""
        try:
            wv = _get_webview()
            file_types = ('EVTX日志文件 (*.evtx)',)
            # 使用新API: FileDialog.OPEN 替代废弃的 OPEN_DIALOG
            dialog_type = getattr(wv, 'OPEN_DIALOG', None)
            if hasattr(wv, 'FileDialog'):
                dialog_type = wv.FileDialog.OPEN
            result = wv.windows[0].create_file_dialog(dialog_type, file_types=file_types)
            
            if result and len(result) > 0:
                file_path = result[0]
                return self.get_file_info(file_path)
            else:
                return {'success': False, 'error': '未选择文件'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def select_log_directory(self) -> dict:
        """打开目录选择对话框并切换当前日志目录"""
        try:
            wv = _get_webview()
            dialog_type = getattr(wv, 'FOLDER_DIALOG', None)
            if hasattr(wv, 'FileDialog'):
                dialog_type = wv.FileDialog.FOLDER

            result = wv.windows[0].create_file_dialog(dialog_type, directory=self.logs_dir)
            if not result or len(result) == 0:
                return {'success': False, 'cancelled': True, 'error': '未选择目录'}

            selected_dir = os.path.abspath(result[0])
            if not os.path.isdir(selected_dir):
                return {'success': False, 'error': f'目录不存在: {selected_dir}'}

            self._update_logs_directory(selected_dir)
            files_result = self.get_log_files()
            files_result['logs_dir'] = selected_dir
            return files_result
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ================= 事件加载API =================
    
    def load_events_paginated(self, file_path: str, page: int = 1, page_size: int = 100,
                              extract_xml: bool = False, sort_field: str = None, sort_direction: str = 'asc') -> dict:
        """分页加载事件"""
        return self.event_service.load_events_paginated(file_path, page, page_size, sort_field, sort_direction)
    
    def get_load_progress(self, file_path: str = None) -> dict:
        """获取加载进度"""
        return self.event_service.get_load_progress(file_path)
    
    def get_available_fields(self, file_path: str, sample_size: int = 100) -> dict:
        """获取可用字段列表"""
        return self.event_service.get_available_fields(file_path, sample_size)
    
    def get_field_labels(self) -> dict:
        """获取所有字段的中文标签"""
        from ..core.static_field_dict import FIELD_DICT
        labels = {}
        for field_name, field_info in FIELD_DICT.items():
            labels[field_name] = field_info.get('label', field_name)
        return {'success': True, 'labels': labels}
    
    # ================= 搜索API =================
    
    def search_events(self, file_path: str, keyword: str, page: int = 1, page_size: int = 100,
                      sort_field: str = None, sort_direction: str = 'asc') -> dict:
        """搜索事件"""
        return self.search_service.search_events(file_path, keyword, page, page_size, sort_field, sort_direction)
    
    def advanced_search_events(self, file_path: str, filters: Dict[str, str], page: int = 1,
                               page_size: int = 100, sort_field: str = None, sort_direction: str = 'asc') -> dict:
        """高级搜索事件"""
        return self.search_service.advanced_search_events(file_path, filters, page, page_size, sort_field, sort_direction)
    
    # ================= 告警规则API =================
    
    def get_alert_rules(self, file_path: str) -> dict:
        """获取告警规则"""
        return self.alert_service.get_alert_rules(file_path)
    
    def save_alert_rules(self, file_path: str, rules: List[dict]) -> dict:
        """保存告警规则"""
        return self.alert_service.save_alert_rules(file_path, rules)
    
    def clear_alert_rules(self, file_path: str) -> dict:
        """清空告警规则"""
        return self.alert_service.clear_alert_rules(file_path)
    
    def get_last_alert_scan(self, file_path: str) -> dict:
        """获取最近一次扫描摘要"""
        return self.alert_service.get_last_alert_scan(file_path)
    
    def save_last_alert_scan(self, file_path: str, summary: dict) -> dict:
        """保存扫描摘要"""
        return self.alert_service.save_last_alert_scan(file_path, summary)
    
    def init_builtin_alert_rules(self, overwrite: bool = False, file_path: str = None) -> dict:
        """初始化内置告警规则"""
        return self.alert_service.init_builtin_alert_rules(overwrite, file_path)
    
    def scan_alerts_from_db(self, file_path: str, scan_limit: int = None, rules: List[dict] = None) -> dict:
        """从数据库扫描告警"""
        return self.alert_service.scan_alerts_from_db(file_path, scan_limit, rules)
    
    def get_scan_progress(self, file_path: str) -> dict:
        """获取扫描进度"""
        return self.alert_service.get_scan_progress(file_path)

    # ================= 缓存管理API =================
    
    def get_cache_info(self) -> dict:
        """获取缓存统计信息"""
        return self.cache_service.get_cache_info()
    
    def clear_all_cache(self) -> dict:
        """清空所有缓存"""
        return self.cache_service.clear_all_cache()
    
    def clear_file_cache(self, file_path: str) -> dict:
        """清空指定文件的缓存"""
        return self.cache_service.clear_file_cache(file_path)
    
    # ================= 统计API =================
    
    def get_statistics_security_login(self, file_path: str, time_range_hours: int = None) -> dict:
        """获取Security日志登录统计"""
        return self.statistics_service.get_security_login_stats(file_path, time_range_hours)
    
    def get_statistics_security_account(self, file_path: str, time_range_hours: int = None) -> dict:
        """获取Security日志账户统计"""
        return self.statistics_service.get_security_account_stats(file_path, time_range_hours)
    
    def get_statistics_security_process(self, file_path: str, time_range_hours: int = None) -> dict:
        """获取Security日志进程统计"""
        return self.statistics_service.get_security_process_stats(file_path, time_range_hours)
    
    def get_statistics_system(self, file_path: str, time_range_hours: int = None) -> dict:
        """获取System日志统计"""
        return self.statistics_service.get_system_stats(file_path, time_range_hours)
    
    def get_statistics_application(self, file_path: str, time_range_hours: int = None) -> dict:
        """获取Application日志统计"""
        return self.statistics_service.get_application_stats(file_path, time_range_hours)
    
    def get_statistics_overview(self, file_path: str, time_range_hours: int = None) -> dict:
        """获取概览统计"""
        return self.statistics_service.get_overview_stats(file_path, time_range_hours)
    
    # ================= 安全预设API =================
    
    def get_security_presets(self) -> dict:
        """获取所有安全预设"""
        try:
            return {
                'success': True,
                'presets': get_all_presets(),
                'categories': PRESET_CATEGORIES,
                'severity_levels': SEVERITY_LEVELS,
                'operators': OPERATORS
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_presets_by_category(self) -> dict:
        """按分类获取预设"""
        try:
            return {
                'success': True,
                'presets_by_category': get_presets_by_category(),
                'categories': PRESET_CATEGORIES
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def apply_security_preset(self, file_path: str, preset_id: str, page: int = 1, page_size: int = 100) -> dict:
        """应用安全预设进行搜索"""
        try:
            preset = get_preset_by_id(preset_id)
            if not preset:
                return {'success': False, 'error': f'预设不存在: {preset_id}'}
            
            conditions = preset.get('conditions', [])
            logic = preset.get('logic', 'AND')
            
            where_clauses = [build_sql_condition(c) for c in conditions]
            where_sql = f' {logic} '.join(where_clauses)
            
            # 使用高级搜索
            filters = {}
            for condition in conditions:
                filters[condition['field']] = condition['value']
            
            result = self.search_service.advanced_search_events(file_path, filters, page, page_size)
            
            if result['success']:
                result['preset_info'] = {
                    'id': preset_id,
                    'name': preset['name'],
                    'description': preset['description'],
                    'severity': preset['severity']
                }
            
            return result
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # ================= 导出API =================
    
    def export_results(self, data: Any, file_name: str = 'export.json') -> dict:
        """导出结果"""
        try:
            import json
            wv = _get_webview()
            
            result = wv.windows[0].create_file_dialog(wv.SAVE_DIALOG, save_filename=file_name)
            
            if result:
                with open(result, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                return {'success': True, 'file_path': result}
            else:
                return {'success': False, 'error': '取消导出'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def export_to_csv(self, evtx_file_path: str, visible_fields: List[str], export_type: str = 'all',
                      search_keyword: str = '', advanced_filters: Dict = None) -> dict:
        """导出CSV数据"""
        try:
            import csv
            
            file_name = os.path.basename(evtx_file_path).replace('.evtx', '')
            if export_type == 'search':
                export_filename = f"{file_name}_搜索.csv"
            elif export_type == 'advanced_search':
                export_filename = f"{file_name}_高级搜索.csv"
            else:
                export_filename = f"{file_name}_全部数据.csv"
            
            try:
                wv = _get_webview()
                result = wv.windows[0].create_file_dialog(wv.SAVE_DIALOG, save_filename=export_filename)
                if result and len(result) > 0:
                    file_path = result[0]
                else:
                    return {'success': False, 'error': '取消导出'}
            except:
                file_path = os.path.join(os.getcwd(), export_filename)
            
            # 获取数据
            all_events = []
            if export_type == 'all':
                result = self.event_service.load_events_paginated(evtx_file_path, 1, 999999)
                if result['success']:
                    all_events = result['events']
            elif export_type == 'search':
                result = self.search_service.search_events(evtx_file_path, search_keyword, 1, 999999)
                if result['success']:
                    all_events = result['events']
            elif export_type == 'advanced_search':
                result = self.search_service.advanced_search_events(evtx_file_path, advanced_filters or {}, 1, 999999)
                if result['success']:
                    all_events = result['events']
            
            if not all_events:
                return {'success': False, 'error': '没有数据可导出'}
            
            # 写入CSV
            with open(file_path, 'w', encoding='utf-8-sig', newline='') as csvfile:
                fieldnames = visible_fields if visible_fields else sorted(set().union(*[e.keys() for e in all_events]))
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for event in all_events:
                    row_data = {f: str(event.get(f, '')).replace('\n', ' ').replace('\r', ' ') for f in fieldnames}
                    writer.writerow(row_data)
            
            return {'success': True, 'file_path': file_path, 'exported_count': len(all_events), 'export_type': export_type}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ================= 窗口控制API =================
    
    def fullscreen(self) -> None:
        """切换全屏"""
        wv = _get_webview()
        wv.windows[0].toggle_fullscreen()
    
    def minimize(self) -> None:
        """最小化窗口"""
        wv = _get_webview()
        wv.windows[0].minimize()
    
    def get_version(self) -> dict:
        return {'version': '1.0.0', 'name': 'FastWinLog'}
    
    # ================= 日志类型检测API =================
    
    def get_log_type_info(self, file_path: str) -> dict:
        """
        获取日志类型信息（通过Channel识别）
        即使文件名改为 sec111.evtx 也能正确识别为Security日志
        """
        try:
            file_name = os.path.basename(file_path)
            
            # 通过Channel检测日志类型
            channel, log_type, is_supported = self.event_service.detect_log_type(file_path)
            
            return {
                'success': True,
                'file_name': file_name,
                'channel': channel,
                'log_type': log_type,
                'is_supported': True,  # All log types are now supported
                'supported_types': SUPPORTED_LOG_TYPES,
                'message': f'Log type: {log_type} (Channel: {channel})'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_supported_log_types(self) -> dict:
        """Get supported log types list - All Windows Event Log types are supported"""
        from ..core.static_field_dict import CHANNEL_TO_LOG_TYPE
        return {
            'success': True,
            'types': SUPPORTED_LOG_TYPES,
            'channel_mapping': CHANNEL_TO_LOG_TYPE,
            'message': 'All Windows Event Log types are supported'
        }
    
    # ================= 预设过滤API =================
    
    def get_preset_filters(self, log_type: str = '') -> dict:
        """获取预设过滤条件"""
        presets = {
            'Security': [
                {'name': '成功登录', 'description': '事件4624，所有成功登录', 'filters': [{'field': 'EventID', 'operator': '=', 'value': '4624'}]},
                {'name': '失败登录', 'description': '事件4625，所有失败的登录尝试', 'filters': [{'field': 'EventID', 'operator': '=', 'value': '4625'}]},
                {'name': '账户注销', 'description': '事件4634，用户注销', 'filters': [{'field': 'EventID', 'operator': '=', 'value': '4634'}]},
                {'name': '特权使用', 'description': '事件4672，分配了特殊权限', 'filters': [{'field': 'EventID', 'operator': '=', 'value': '4672'}]},
            ],
            'System': [
                {'name': '系统错误', 'description': '所有错误级别事件', 'filters': [{'field': 'Level', 'operator': '=', 'value': '错误'}]},
                {'name': '系统启动', 'description': '事件6009，系统启动', 'filters': [{'field': 'EventID', 'operator': '=', 'value': '6009'}]},
                {'name': '系统关机', 'description': '事件1074，系统关机或重启', 'filters': [{'field': 'EventID', 'operator': '=', 'value': '1074'}]},
            ]
        }
        
        if 'Security' in log_type:
            return {'success': True, 'presets': presets['Security']}
        elif 'System' in log_type:
            return {'success': True, 'presets': presets['System']}
        else:
            all_presets = []
            for p in presets.values():
                all_presets.extend(p)
            return {'success': True, 'presets': all_presets}
    
    def filter_events_advanced(self, file_path: str, filters: List[dict], page: int = 1, page_size: int = 100) -> dict:
        """高级条件过滤"""
        # 转换filters格式
        filter_dict = {}
        for f in filters:
            filter_dict[f.get('field')] = f.get('value')
        return self.search_service.advanced_search_events(file_path, filter_dict, page, page_size)
    
    # ================= 列设置API =================
    
    def save_column_settings(self, file_path: str, settings: dict) -> dict:
        """保存列设置到SQLite"""
        try:
            import sqlite3
            import json
            from datetime import datetime
            
            db_path = self.sqlite_repo.get_cache_path(file_path)
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
            """)
            
            settings_json = json.dumps(settings, ensure_ascii=False)
            updated_at = datetime.now().isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO user_settings (key, value, updated_at)
                VALUES ('column_settings', ?, ?)
            """, (settings_json, updated_at))
            
            conn.commit()
            conn.close()
            
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_column_settings(self, file_path: str) -> dict:
        """从SQLite加载列设置"""
        try:
            import sqlite3
            import json
            
            db_path = self.sqlite_repo.get_cache_path(file_path)
            
            if not os.path.exists(db_path):
                return {'success': True, 'settings': None}
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='user_settings'
            """)
            if not cursor.fetchone():
                conn.close()
                return {'success': True, 'settings': None}
            
            cursor.execute("""
                SELECT value FROM user_settings WHERE key = 'column_settings'
            """)
            row = cursor.fetchone()
            conn.close()
            
            if row and row[0]:
                settings = json.loads(row[0])
                return {'success': True, 'settings': settings}
            else:
                return {'success': True, 'settings': None}
                
        except Exception as e:
            return {'success': False, 'error': str(e), 'settings': None}
    
    # ================= 告警规则导入导出API =================
    
    def export_alert_rules_to_file(self, file_path: str, rules: List[dict]) -> dict:
        """使用文件对话框导出告警规则"""
        try:
            import json
            from datetime import datetime
            
            wv = _get_webview()
            result = wv.windows[0].create_file_dialog(
                wv.SAVE_DIALOG,
                save_filename=f'alert_rules_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            )
            
            if isinstance(result, tuple):
                save_path = result[0] if result else None
            else:
                save_path = result
            
            if not save_path:
                return {'success': False, 'error': '用户取消'}
            
            export_data = {
                'version': '1.0',
                'exportedAt': datetime.now().isoformat(),
                'source': 'Windows Event Log Analyzer',
                'sourceFile': os.path.basename(file_path),
                'ruleCount': len(rules),
                'rules': rules
            }
            
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return {'success': True, 'file_path': save_path, 'rule_count': len(rules)}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def import_alert_rules_from_file(self) -> dict:
        """使用文件对话框导入告警规则"""
        try:
            import json
            
            wv = _get_webview()
            # 使用新API: FileDialog.OPEN 替代废弃的 OPEN_DIALOG
            dialog_type = getattr(wv, 'OPEN_DIALOG', None)
            if hasattr(wv, 'FileDialog'):
                dialog_type = wv.FileDialog.OPEN
            result = wv.windows[0].create_file_dialog(
                dialog_type,
                file_types=('JSON文件 (*.json)',)
            )
            
            if not result:
                return {'success': False, 'error': '用户取消'}
            
            if isinstance(result, (tuple, list)):
                file_path = result[0] if result else None
            else:
                file_path = result
                
            if not file_path:
                return {'success': False, 'error': '用户取消'}
            
            with open(file_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            if 'version' not in import_data:
                return {'success': False, 'error': '无效的规则文件：缺少版本信息'}
            
            if 'rules' not in import_data:
                return {'success': False, 'error': '无效的规则文件：缺少规则数据'}
            
            rules = import_data.get('rules', [])
            
            for i, rule in enumerate(rules):
                required_fields = ['id', 'name', 'enabled', 'severity', 'conditions']
                for field in required_fields:
                    if field not in rule:
                        return {'success': False, 'error': f'规则{i+1}缺少必需字段：{field}'}
            
            return {
                'success': True,
                'rules': rules,
                'version': import_data.get('version'),
                'ruleCount': len(rules),
                'sourceFile': import_data.get('sourceFile', '未知'),
                'exportedAt': import_data.get('exportedAt', '未知')
            }
            
        except json.JSONDecodeError as e:
            return {'success': False, 'error': f'JSON解析错误：{str(e)}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    # ================= 历史记录管理API =================
    
    def delete_file_history(self, file_path: str) -> dict:
        """删除文件历史记录"""
        try:
            # 清理SQLite缓存
            self.sqlite_repo.clear_cache(file_path)
            
            # 清理内存缓存
            self.memory_manager.release(file_path)
            
            # 清理进度状态
            self.progress_tracker.clear(file_path)
            
            return {'success': True, 'message': '已删除历史记录'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
