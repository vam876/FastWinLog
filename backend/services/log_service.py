#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Log file management service"""

import os
import sqlite3
from typing import List, Dict, Any, Optional
from ..core.log_descriptions import get_log_description
from ..repositories.sqlite_repository import SqliteRepository
from ..utils.memory_manager import MemoryManager


class LogService:
    """Log file management service"""
    
    # Import restrictions have been removed. Keep the hook for future use.
    BLACKLIST_PATTERNS = []
    
    def __init__(self, base_dir: str, sqlite_repo: SqliteRepository, memory_manager: MemoryManager):
        self.base_dir = base_dir
        self.logs_dir = os.path.join(base_dir, 'logs')
        self.sqlite_repo = sqlite_repo
        self.memory = memory_manager

    def set_logs_dir(self, logs_dir: str) -> None:
        """Update the active logs directory for the current session."""
        if not logs_dir:
            self.logs_dir = os.path.join(self.base_dir, 'logs')
            return

        self.logs_dir = os.path.abspath(logs_dir)

    def get_logs_dir(self) -> str:
        """Return the active logs directory."""
        return self.logs_dir
    
    def _is_blacklisted(self, filename: str) -> bool:
        """Check if file is in blacklist"""
        if not self.BLACKLIST_PATTERNS:
            return False
        filename_lower = filename.lower()
        for pattern in self.BLACKLIST_PATTERNS:
            if pattern.lower() in filename_lower:
                return True
        return False
    
    def get_log_files(self, include_loaded: bool = True) -> dict:
        """Get log files list"""
        try:
            files = []
            seen_paths = set()
            
            # 1. Add files from logs directory
            if os.path.exists(self.logs_dir):
                for filename in os.listdir(self.logs_dir):
                    if filename.endswith('.evtx'):
                        # Skip blacklisted files
                        if self._is_blacklisted(filename):
                            continue
                        
                        log_name = filename.replace('.evtx', '').replace('%4', '/')
                        file_path = os.path.join(self.logs_dir, filename)
                        
                        if os.path.exists(file_path):
                            file_size = os.path.getsize(file_path)
                            desc = get_log_description(log_name)
                            
                            files.append({
                                'file_path': file_path,
                                'file_name': filename,
                                'log_name': log_name,
                                'file_size': file_size,
                                'file_size_mb': round(file_size / (1024 * 1024), 2),
                                'display_name': desc['name'],
                                'description': desc['description'],
                                'category': desc['category'],
                                'importance': desc['importance'],
                                'source': 'logs'
                            })
                            seen_paths.add(os.path.normpath(file_path).lower())
            
            # 2. Add loaded files
            if include_loaded:
                # From SQLite cache
                self._add_cached_files(files, seen_paths)
                
                # From memory cache
                for file_path in self.memory.get_all_cached_files():
                    # Skip blacklisted files
                    if self._is_blacklisted(os.path.basename(file_path)):
                        continue
                    
                    norm_path = os.path.normpath(file_path).lower()
                    if norm_path not in seen_paths and os.path.exists(file_path):
                        self._add_file_info(files, file_path, 'loaded')
                        seen_paths.add(norm_path)
            
            # 排序
            importance_order = {'high': 0, 'medium': 1, 'low': 2}
            source_order = {'logs': 0, 'loaded': 1, 'history': 2, 'cached': 3}
            files.sort(key=lambda x: (
                source_order.get(x.get('source', 'logs'), 4),
                importance_order.get(x['importance'], 3),
                x['log_name']
            ))
            
            # 空目录提示
            empty_hint = None
            logs_files = [f for f in files if f.get('source') == 'logs']
            if len(logs_files) == 0:
                empty_hint = self._build_empty_hint()
            
            return {
                'success': True,
                'files': files,
                'total': len(files),
                'logs_count': len(logs_files),
                'logs_dir': self.logs_dir,
                'empty_hint': empty_hint
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _add_cached_files(self, files: List[dict], seen_paths: set) -> None:
        """Add cached files"""
        cache_dir = self.sqlite_repo.cache_dir
        if not os.path.exists(cache_dir):
            return
        
        for cache_file in os.listdir(cache_dir):
            if cache_file.endswith('.cache.db'):
                # Skip blacklisted files
                if self._is_blacklisted(cache_file):
                    continue
                
                try:
                    cache_path = os.path.join(cache_dir, cache_file)
                    conn = sqlite3.connect(cache_path, timeout=5.0)
                    cursor = conn.cursor()
                    
                    cursor.execute("SELECT value FROM metadata WHERE key = 'source_file'")
                    row = cursor.fetchone()
                    
                    if row:
                        source_file = row[0]
                        norm_path = os.path.normpath(source_file).lower()
                        
                        if norm_path not in seen_paths:
                            cursor.execute("SELECT value FROM metadata WHERE key = 'total_events'")
                            total_events_row = cursor.fetchone()
                            total_events = int(total_events_row[0]) if total_events_row else 0
                            
                            conn.close()
                            
                            file_exists = os.path.exists(source_file)
                            file_size = os.path.getsize(source_file) if file_exists else 0
                            
                            filename = os.path.basename(source_file)
                            log_name = filename.replace('.evtx', '').replace('%4', '/')
                            desc = get_log_description(log_name)
                            
                            files.append({
                                'file_path': source_file,
                                'file_name': filename,
                                'log_name': log_name,
                                'file_size': file_size,
                                'file_size_mb': round(file_size / (1024 * 1024), 2) if file_exists else 0,
                                'display_name': desc['name'],
                                'description': desc['description'],
                                'category': desc['category'],
                                'importance': desc['importance'],
                                'source': 'history',
                                'is_cached': True,
                                'file_exists': file_exists,
                                'total_events': total_events
                            })
                            seen_paths.add(norm_path)
                        else:
                            conn.close()
                except:
                    pass
    
    def _add_file_info(self, files: List[dict], file_path: str, source: str) -> None:
        """添加文件信息"""
        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            log_name = filename.replace('.evtx', '').replace('%4', '/')
            desc = get_log_description(log_name)
            
            files.append({
                'file_path': file_path,
                'file_name': filename,
                'log_name': log_name,
                'file_size': file_size,
                'file_size_mb': round(file_size / (1024 * 1024), 2),
                'display_name': desc['name'],
                'description': desc['description'],
                'category': desc['category'],
                'importance': desc['importance'],
                'source': source,
                'is_cached': True
            })
        except:
            pass
    
    def _build_empty_hint(self) -> dict:
        """构建空目录提示"""
        system_log_path = r'C:\Windows\System32\winevt\Logs'
        default_logs_dir = os.path.join(self.base_dir, 'logs')
        is_default_logs_dir = os.path.normpath(self.logs_dir).lower() == os.path.normpath(default_logs_dir).lower()

        if is_default_logs_dir:
            title = '当前 logs 目录为空'
            message = '请将 Windows 日志文件（.evtx）放入程序运行目录下的 logs 文件夹中'
        else:
            title = '当前选择目录为空'
            message = '当前选择的目录中没有找到 .evtx 日志文件，请重新选择目录或复制日志文件后刷新'

        return {
            'title': title,
            'message': message,
            'logs_dir': self.logs_dir,
            'system_log_path': system_log_path,
            'tips': [
                '支持所有 Windows 事件日志类型（.evtx 格式）',
                f'当前日志目录：{self.logs_dir}',
                f'系统默认日志目录：{system_log_path}'
            ]
        }
    
    def get_file_info(self, file_path: str) -> dict:
        """获取文件详细信息"""
        try:
            if not os.path.exists(file_path):
                return {'success': False, 'error': '文件不存在'}
            
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            log_name = filename.replace('.evtx', '').replace('%4', '/')
            desc = get_log_description(log_name)
            
            info = {
                'file_path': file_path,
                'file_name': filename,
                'file_size': file_size,
                'file_size_mb': round(file_size / (1024 * 1024), 2),
                **desc
            }
            
            return {'success': True, 'info': info}
        except Exception as e:
            return {'success': False, 'error': str(e)}
