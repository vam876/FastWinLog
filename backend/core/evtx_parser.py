#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
FastWinLog - EVTX Parser
Version: 1.0.0
Repository: https://github.com/vam876/FastWinLog
"""

import pyevtx
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Callable, Tuple
from .static_field_dict import (
    FIELD_DICT, CHANNEL_TO_LOG_TYPE, SUPPORTED_LOG_TYPES,
    get_log_type_by_channel, is_supported_channel
)


class EvtxParser:
    """EVTX文件解析器 - 通过Channel识别日志类型"""
    
    NS = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    USERDATA_ALIAS_FIELDS = {
        'EventData_IpAddress': (
            'EventData_IpAddress', 'EventData_Address', 'EventData_ClientAddress',
            'EventData_ClientIP', 'IpAddress', 'Address', 'ClientAddress', 'ClientIP'
        ),
        'EventData_TargetUserName': (
            'EventData_TargetUserName', 'EventData_User', 'TargetUserName', 'User', 'AccountName'
        ),
        'EventData_SessionID': (
            'EventData_SessionID', 'EventData_Session', 'SessionID', 'Session'
        ),
    }
    
    LEVEL_MAP = {
        '0': '日志已启用',
        '1': '严重',
        '2': '错误',
        '3': '警告',
        '4': '信息',
        '5': '详细'
    }
    
    def detect_log_type(self, file_path: str) -> Tuple[str, str, bool]:
        """
        检测日志类型（通过读取Channel字段）
        
        Returns:
            (channel, log_type, is_supported)
        """
        evtx_file = pyevtx.file()
        evtx_file.open(file_path)
        
        channel = None
        try:
            if evtx_file.get_number_of_records() > 0:
                record = evtx_file.get_record(0)
                xml_string = record.get_xml_string()
                
                if xml_string:
                    root = ET.fromstring(xml_string)
                    system = root.find('evt:System', self.NS)
                    if system is not None:
                        ch = system.find('evt:Channel', self.NS)
                        if ch is not None and ch.text:
                            channel = ch.text
        finally:
            evtx_file.close()
        
        log_type = get_log_type_by_channel(channel) if channel else 'Other'
        is_supported = True
        
        return channel, log_type, is_supported
    
    def parse_file(self, file_path: str, progress_callback: Optional[Callable] = None) -> List[Dict]:
        """解析整个文件"""
        events = []
        
        evtx_file = pyevtx.file()
        evtx_file.open(file_path)
        
        try:
            total_records = evtx_file.get_number_of_records()
            
            for i in range(total_records):
                record = evtx_file.get_record(i)
                event = self.parse_record(record)
                events.append(event)
                
                if progress_callback and (i + 1) % 100 == 0:
                    progress_callback(i + 1, total_records)
        finally:
            evtx_file.close()
        
        return events
    
    def parse_record(self, record) -> Dict:
        """解析单条记录 - 只提取静态字段"""
        event_data = {}
        
        try:
            # 基础字段
            event_data['EventID'] = str(record.get_event_identifier())
            event_data['Computer'] = record.get_computer_name()
            event_data['RecordID'] = str(record.get_identifier())
            
            try:
                written_time = record.get_written_time()
                if written_time:
                    event_data['TimeCreated'] = str(written_time)
            except:
                pass
            
            try:
                level = str(record.get_event_level())
                event_data['Level'] = self.LEVEL_MAP.get(level, level)
            except:
                pass
            
            # 解析XML获取更多字段
            xml_string = record.get_xml_string()
            
            if xml_string:
                self._parse_xml_fields(xml_string, event_data)
        
        except Exception as e:
            event_data['_error'] = str(e)
        
        return event_data
    
    def _parse_xml_fields(self, xml_string: str, event_data: Dict) -> None:
        """从XML中提取静态字段"""
        try:
            root = ET.fromstring(xml_string)
            
            # System节点
            system = root.find('evt:System', self.NS)
            if system:
                # Provider
                provider = system.find('evt:Provider', self.NS)
                if provider is not None:
                    event_data['Provider_Name'] = provider.get('Name', '')
                    event_data['Provider_Guid'] = provider.get('Guid', '')
                    event_data['Provider_EventSourceName'] = provider.get('EventSourceName', '')
                
                # Channel
                channel = system.find('evt:Channel', self.NS)
                if channel is not None and channel.text:
                    event_data['Channel'] = channel.text
                
                # Execution
                execution = system.find('evt:Execution', self.NS)
                if execution is not None:
                    event_data['ProcessID'] = execution.get('ProcessID', '')
                    event_data['ThreadID'] = execution.get('ThreadID', '')
                
                # Security
                security = system.find('evt:Security', self.NS)
                if security is not None:
                    event_data['UserID'] = security.get('UserID', '')
                
                # TimeCreated
                time_created = system.find('evt:TimeCreated', self.NS)
                if time_created is not None:
                    event_data['TimeCreated_SystemTime'] = time_created.get('SystemTime', '')
            
            # EventData节点 - 提取所有字段（用于统计和搜索）
            event_data_node = root.find('evt:EventData', self.NS)
            if event_data_node is not None:
                data_idx = 0
                for data in event_data_node.findall('evt:Data', self.NS):
                    name = data.get('Name')
                    value = data.text if data.text else ''
                    
                    if name:
                        field_key = f'EventData_{name}'
                        event_data[field_key] = value
                    elif value:
                        # 无名称的Data节点，按顺序编号
                        event_data[f'EventData_Data{data_idx}'] = value
                        
                        # 尝试解析键值对格式（PowerShell日志等）
                        # 格式如: "ProviderName=Registry\n\tNewProviderState=Started"
                        if '=' in value and ('\n' in value or '\t' in value):
                            self._parse_key_value_data(value, event_data)
                        
                        data_idx += 1
            
            # UserData节点 - 提取所有字段
            user_data_node = root.find('evt:UserData', self.NS)
            if user_data_node is not None:
                for child in user_data_node:
                    for subchild in child:
                        tag = subchild.tag.split('}')[-1] if '}' in subchild.tag else subchild.tag
                        value = subchild.text if subchild.text else ''
                        
                        if tag and value:
                            event_data[tag] = value

                            prefixed_tag = f'EventData_{tag}'
                            if prefixed_tag not in event_data:
                                event_data[prefixed_tag] = value

            self._normalize_alias_fields(event_data)
        
        except Exception as e:
            pass

    def _normalize_alias_fields(self, event_data: Dict) -> None:
        """对不同日志通道中同义字段做标准化补齐。"""
        for canonical_name, aliases in self.USERDATA_ALIAS_FIELDS.items():
            canonical_value = ''
            for alias_name in aliases:
                alias_value = event_data.get(alias_name)
                if alias_value not in (None, ''):
                    canonical_value = alias_value
                    break

            if not canonical_value:
                continue

            for alias_name in aliases:
                event_data.setdefault(alias_name, canonical_value)
    
    def _parse_key_value_data(self, value: str, event_data: Dict) -> None:
        """解析键值对格式的数据（如PowerShell日志）"""
        try:
            # 按换行和制表符分割
            lines = value.replace('\t', '\n').split('\n')
            for line in lines:
                line = line.strip()
                if '=' in line:
                    # 分割键值对
                    eq_pos = line.find('=')
                    key = line[:eq_pos].strip()
                    val = line[eq_pos+1:].strip()
                    
                    if key and val:
                        # 添加到event_data，使用EventData_前缀
                        field_key = f'EventData_{key}'
                        # 避免覆盖已有字段
                        if field_key not in event_data:
                            event_data[field_key] = val
        except:
            pass
    
    def count_records(self, file_path: str) -> int:
        """快速统计记录总数"""
        evtx_file = pyevtx.file()
        evtx_file.open(file_path)
        
        try:
            return evtx_file.get_number_of_records()
        finally:
            evtx_file.close()
    
    def parse_range(self, file_path: str, start_idx: int, end_idx: int) -> List[Dict]:
        """解析指定范围的记录"""
        events = []
        
        evtx_file = pyevtx.file()
        evtx_file.open(file_path)
        
        try:
            total_records = evtx_file.get_number_of_records()
            end_idx = min(end_idx, total_records)
            
            for i in range(start_idx, end_idx):
                record = evtx_file.get_record(i)
                event = self.parse_record(record)
                events.append(event)
        finally:
            evtx_file.close()
        
        return events
