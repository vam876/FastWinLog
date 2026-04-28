#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
FastWinLog - Static Field Dictionary
Version: 1.0.0
Repository: https://github.com/vam876/FastWinLog
"""

# Channel to log type mapping
CHANNEL_TO_LOG_TYPE = {
    'Security': 'Security',
    'Application': 'Application',
    'System': 'System',
    'Microsoft-Windows-PowerShell/Operational': 'PowerShell',
    'Windows PowerShell': 'PowerShell',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational': 'TerminalServices',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational': 'TerminalServices',
    'Microsoft-Windows-TerminalServices-RDPClient/Operational': 'TerminalServices',
    'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational': 'TerminalServices',
}

# Supported log types - All Windows Event Log types are supported
SUPPORTED_LOG_TYPES = [
    'Security', 
    'Application', 
    'System', 
    'PowerShell',
    'TerminalServices',
    'Setup',
    'Forwarded Events',
    'Windows Defender',
    'DNS Server',
    'Active Directory',
    'File Replication Service',
    'DFS Replication',
    'Hardware Events',
    'Internet Explorer',
    'Key Management Service',
    'Media Center',
    'Windows Backup',
    'Windows Update',
    'Other'
]

# Default visible fields
DEFAULT_VISIBLE_FIELDS = [
    'TimeCreated',
    'EventID',
    '_event_name',
    '_event_description',
    'Level',
    'Provider_Name',
    'Computer'
]

# Recommended fields by log type
RECOMMENDED_FIELDS_BY_TYPE = {
    'Security': [
        'TimeCreated', 'EventID', '_event_name', 'Level',
        'EventData_TargetUserName', 'EventData_IpAddress', 'EventData_LogonType'
    ],
    'Application': [
        'TimeCreated', 'EventID', '_event_name', 'Level',
        'Provider_Name', 'Computer'
    ],
    'System': [
        'TimeCreated', 'EventID', '_event_name', 'Level',
        'Provider_Name', 'EventData_param1', 'EventData_ServiceName'
    ],
    'PowerShell': [
        'TimeCreated', 'EventID', '_event_name', 'Level',
        'EventData_ScriptBlockText', 'EventData_CommandName'
    ],
    'TerminalServices': [
        'TimeCreated', 'EventID', '_event_name', 'Level',
        'EventData_TargetUserName', 'EventData_SessionID', 'EventData_IpAddress'
    ],
}

# Base fields (common to all logs)
BASE_FIELDS = {
    'RecordID': {'label': '记录ID', 'group': '基础信息', 'width': 80},
    'EventID': {'label': '事件ID', 'group': '基础信息', 'width': 80},
    'Level': {'label': '级别', 'group': '基础信息', 'width': 80},
    'TimeCreated': {'label': '创建时间', 'group': '时间信息', 'width': 180},
    'TimeCreated_SystemTime': {'label': '系统时间', 'group': '时间信息', 'width': 180},
    'Provider_Name': {'label': '提供程序名称', 'group': '提供者信息', 'width': 200},
    'Provider_Guid': {'label': '提供程序GUID', 'group': '提供者信息', 'width': 280},
    'Provider_EventSourceName': {'label': '事件源名称', 'group': '提供者信息', 'width': 150},
    'Computer': {'label': '计算机', 'group': '基础信息', 'width': 150},
    'Channel': {'label': '通道', 'group': '基础信息', 'width': 120},
    'ProcessID': {'label': '进程ID', 'group': '执行信息', 'width': 80},
    'ThreadID': {'label': '线程ID', 'group': '执行信息', 'width': 80},
    'UserID': {'label': '用户ID', 'group': '安全信息', 'width': 150},
    # 事件描述字段
    '_event_name': {'label': '事件名称', 'group': '事件描述', 'width': 200},
    '_event_description': {'label': '事件描述', 'group': '事件描述', 'width': 300},
    '_event_category': {'label': '事件类别', 'group': '事件描述', 'width': 100},
    '_event_severity': {'label': '严重程度', 'group': '事件描述', 'width': 80},
}

# Security log fields
SECURITY_FIELDS = {
    'EventData_AlgorithmName': {'label': '算法名称', 'group': '加密信息', 'width': 120},
    'EventData_AuthenticationPackageName': {'label': '认证包名称', 'group': '登录信息', 'width': 150},
    'EventData_CallerProcessId': {'label': '调用进程ID', 'group': '进程信息', 'width': 100},
    'EventData_CallerProcessName': {'label': '调用进程名', 'group': '进程信息', 'width': 200},
    'EventData_ClientCreationTime': {'label': '客户端创建时间', 'group': '时间信息', 'width': 150},
    'EventData_ClientProcessId': {'label': '客户端进程ID', 'group': '进程信息', 'width': 100},
    'EventData_CountOfCredentialsReturned': {'label': '返回凭据数', 'group': '凭据信息', 'width': 100},
    'EventData_ElevatedToken': {'label': '提升令牌', 'group': '登录信息', 'width': 100},
    'EventData_ImpersonationLevel': {'label': '模拟级别', 'group': '登录信息', 'width': 120},
    'EventData_IpAddress': {'label': 'IP地址', 'group': '网络信息', 'width': 120},
    'EventData_IpPort': {'label': 'IP端口', 'group': '网络信息', 'width': 80},
    'EventData_KeyFilePath': {'label': '密钥文件路径', 'group': '加密信息', 'width': 200},
    'EventData_KeyLength': {'label': '密钥长度', 'group': '登录信息', 'width': 80},
    'EventData_KeyName': {'label': '密钥名称', 'group': '加密信息', 'width': 150},
    'EventData_KeyType': {'label': '密钥类型', 'group': '加密信息', 'width': 100},
    'EventData_LmPackageName': {'label': 'LM包名', 'group': '登录信息', 'width': 120},
    'EventData_LogonGuid': {'label': '登录GUID', 'group': '登录信息', 'width': 280},
    'EventData_LogonProcessName': {'label': '登录进程名', 'group': '登录信息', 'width': 120},
    'EventData_LogonType': {'label': '登录类型', 'group': '登录信息', 'width': 80},
    'EventData_NewTime': {'label': '新时间', 'group': '时间信息', 'width': 150},
    'EventData_Operation': {'label': '操作', 'group': '操作信息', 'width': 150},
    'EventData_PreviousTime': {'label': '之前时间', 'group': '时间信息', 'width': 150},
    'EventData_PrivilegeList': {'label': '权限列表', 'group': '权限信息', 'width': 200},
    'EventData_ProcessCreationTime': {'label': '进程创建时间', 'group': '进程信息', 'width': 150},
    'EventData_ProcessId': {'label': '进程ID', 'group': '进程信息', 'width': 100},
    'EventData_ProcessName': {'label': '进程名称', 'group': '进程信息', 'width': 200},
    'EventData_ProviderName': {'label': '提供程序名', 'group': '提供者信息', 'width': 150},
    'EventData_ReadOperation': {'label': '读操作', 'group': '操作信息', 'width': 100},
    'EventData_RestrictedAdminMode': {'label': '受限管理模式', 'group': '登录信息', 'width': 120},
    'EventData_ReturnCode': {'label': '返回码', 'group': '状态信息', 'width': 100},
    'EventData_SubjectDomainName': {'label': '主体域名', 'group': '主体信息', 'width': 120},
    'EventData_SubjectLogonId': {'label': '主体登录ID', 'group': '主体信息', 'width': 120},
    'EventData_SubjectUserName': {'label': '主体用户名', 'group': '主体信息', 'width': 120},
    'EventData_SubjectUserSid': {'label': '主体用户SID', 'group': '主体信息', 'width': 200},
    'EventData_TargetDomainName': {'label': '目标域名', 'group': '目标信息', 'width': 120},
    'EventData_TargetInfo': {'label': '目标信息', 'group': '目标信息', 'width': 150},
    'EventData_TargetLinkedLogonId': {'label': '目标链接登录ID', 'group': '目标信息', 'width': 150},
    'EventData_TargetLogonGuid': {'label': '目标登录GUID', 'group': '目标信息', 'width': 280},
    'EventData_TargetLogonId': {'label': '目标登录ID', 'group': '目标信息', 'width': 120},
    'EventData_TargetName': {'label': '目标名称', 'group': '目标信息', 'width': 150},
    'EventData_TargetOutboundDomainName': {'label': '目标出站域名', 'group': '目标信息', 'width': 150},
    'EventData_TargetOutboundUserName': {'label': '目标出站用户名', 'group': '目标信息', 'width': 150},
    'EventData_TargetServerName': {'label': '目标服务器名', 'group': '目标信息', 'width': 150},
    'EventData_TargetSid': {'label': '目标SID', 'group': '目标信息', 'width': 200},
    'EventData_TargetUserName': {'label': '目标用户名', 'group': '目标信息', 'width': 120},
    'EventData_TargetUserSid': {'label': '目标用户SID', 'group': '目标信息', 'width': 200},
    'EventData_TransmittedServices': {'label': '传输服务', 'group': '服务信息', 'width': 150},
    'EventData_Type': {'label': '类型', 'group': '基础信息', 'width': 100},
    'EventData_VirtualAccount': {'label': '虚拟账户', 'group': '账户信息', 'width': 100},
    'EventData_WorkstationName': {'label': '工作站名', 'group': '网络信息', 'width': 120},
}

# System log fields
SYSTEM_FIELDS = {
    'AddServiceStatus': {'label': '添加服务状态', 'group': '服务信息', 'width': 120},
    'DeviceInstanceID': {'label': '设备实例ID', 'group': '设备信息', 'width': 200},
    'DriverFileName': {'label': '驱动文件名', 'group': '驱动信息', 'width': 150},
    'PrimaryService': {'label': '主服务', 'group': '服务信息', 'width': 150},
    'ServiceName': {'label': '服务名称', 'group': '服务信息', 'width': 150},
    'UpdateService': {'label': '更新服务', 'group': '服务信息', 'width': 150},
    'EventData_AccountName': {'label': '账户名', 'group': '账户信息', 'width': 120},
    'EventData_BootMode': {'label': '启动模式', 'group': '启动信息', 'width': 100},
    'EventData_BootType': {'label': '启动类型', 'group': '启动信息', 'width': 100},
    'EventData_BuildVersion': {'label': '构建版本', 'group': '版本信息', 'width': 100},
    'EventData_DCName': {'label': 'DC名称', 'group': '域信息', 'width': 150},
    'EventData_DeviceName': {'label': '设备名称', 'group': '设备信息', 'width': 150},
    'EventData_DriveName': {'label': '驱动器名', 'group': '设备信息', 'width': 100},
    'EventData_ErrorMessage': {'label': '错误消息', 'group': '错误信息', 'width': 200},
    'EventData_ErrorSource': {'label': '错误来源', 'group': '错误信息', 'width': 150},
    'EventData_FinalStatus': {'label': '最终状态', 'group': '状态信息', 'width': 100},
    'EventData_Group': {'label': '组', 'group': '组信息', 'width': 100},
    'EventData_HiveName': {'label': '注册表项名', 'group': '注册表信息', 'width': 200},
    'EventData_ImagePath': {'label': '映像路径', 'group': '进程信息', 'width': 200},
    'EventData_MajorVersion': {'label': '主版本', 'group': '版本信息', 'width': 80},
    'EventData_MinorVersion': {'label': '次版本', 'group': '版本信息', 'width': 80},
    'EventData_NewTime': {'label': '新时间', 'group': '时间信息', 'width': 150},
    'EventData_OldTime': {'label': '旧时间', 'group': '时间信息', 'width': 150},
    'EventData_ProcessID': {'label': '进程ID', 'group': '进程信息', 'width': 80},
    'EventData_ProcessName': {'label': '进程名称', 'group': '进程信息', 'width': 200},
    'EventData_QfeVersion': {'label': 'QFE版本', 'group': '版本信息', 'width': 80},
    'EventData_Reason': {'label': '原因', 'group': '状态信息', 'width': 150},
    'EventData_ServiceName': {'label': '服务名称', 'group': '服务信息', 'width': 150},
    'EventData_ServiceType': {'label': '服务类型', 'group': '服务信息', 'width': 100},
    'EventData_ServiceVersion': {'label': '服务版本', 'group': '服务信息', 'width': 100},
    'EventData_ShutdownReason': {'label': '关机原因', 'group': '关机信息', 'width': 150},
    'EventData_StartTime': {'label': '开始时间', 'group': '时间信息', 'width': 150},
    'EventData_StartType': {'label': '启动类型', 'group': '服务信息', 'width': 100},
    'EventData_State': {'label': '状态', 'group': '状态信息', 'width': 100},
    'EventData_Status': {'label': '状态码', 'group': '状态信息', 'width': 100},
    'EventData_StopTime': {'label': '停止时间', 'group': '时间信息', 'width': 150},
    'EventData_TimeProvider': {'label': '时间提供程序', 'group': '时间信息', 'width': 150},
    'EventData_UserSid': {'label': '用户SID', 'group': '用户信息', 'width': 200},
    'EventData_Version': {'label': '版本', 'group': '版本信息', 'width': 80},
    'EventData_param1': {'label': '参数1', 'group': '参数信息', 'width': 150},
    'EventData_param2': {'label': '参数2', 'group': '参数信息', 'width': 150},
    'EventData_param3': {'label': '参数3', 'group': '参数信息', 'width': 150},
    'EventData_param4': {'label': '参数4', 'group': '参数信息', 'width': 150},
    'EventData_param5': {'label': '参数5', 'group': '参数信息', 'width': 150},
    'EventData_param6': {'label': '参数6', 'group': '参数信息', 'width': 150},
    'EventData_param7': {'label': '参数7', 'group': '参数信息', 'width': 150},
}

# Application log fields
APPLICATION_FIELDS = {
    # Application logs mainly use base fields
}

# PowerShell log fields
POWERSHELL_FIELDS = {
    'EventData_ScriptBlockText': {'label': '脚本块文本', 'group': 'PowerShell', 'width': 400},
    'EventData_ScriptBlockId': {'label': '脚本块ID', 'group': 'PowerShell', 'width': 280},
    'EventData_Path': {'label': '路径', 'group': 'PowerShell', 'width': 200},
    'EventData_HostName': {'label': '主机名', 'group': 'PowerShell', 'width': 150},
    'EventData_HostVersion': {'label': '主机版本', 'group': 'PowerShell', 'width': 100},
    'EventData_HostId': {'label': '主机ID', 'group': 'PowerShell', 'width': 280},
    'EventData_HostApplication': {'label': '主机应用', 'group': 'PowerShell', 'width': 300},
    'EventData_EngineVersion': {'label': '引擎版本', 'group': 'PowerShell', 'width': 100},
    'EventData_RunspaceId': {'label': '运行空间ID', 'group': 'PowerShell', 'width': 280},
    'EventData_PipelineId': {'label': '管道ID', 'group': 'PowerShell', 'width': 100},
    'EventData_CommandName': {'label': '命令名称', 'group': 'PowerShell', 'width': 150},
    'EventData_CommandType': {'label': '命令类型', 'group': 'PowerShell', 'width': 100},
    'EventData_CommandPath': {'label': '命令路径', 'group': 'PowerShell', 'width': 200},
    'EventData_SequenceNumber': {'label': '序列号', 'group': 'PowerShell', 'width': 80},
    'EventData_NewEngineState': {'label': '新引擎状态', 'group': 'PowerShell', 'width': 100},
    'EventData_PreviousEngineState': {'label': '之前引擎状态', 'group': 'PowerShell', 'width': 120},
}

# TerminalServices / Remote Desktop log fields
TERMINAL_SERVICES_FIELDS = {
    'User': {'label': '用户', 'group': '远程桌面', 'width': 180},
    'Address': {'label': 'IP地址', 'group': '网络信息', 'width': 140},
    'SessionID': {'label': '会话ID', 'group': '远程桌面', 'width': 100},
    'ClientAddress': {'label': '客户端地址', 'group': '网络信息', 'width': 160},
    'ClientIP': {'label': '客户端IP', 'group': '网络信息', 'width': 140},
    'EventData_User': {'label': '用户', 'group': '远程桌面', 'width': 180},
    'EventData_Address': {'label': 'IP地址', 'group': '网络信息', 'width': 140},
    'EventData_SessionID': {'label': '会话ID', 'group': '远程桌面', 'width': 100},
    'EventData_Session': {'label': '会话', 'group': '远程桌面', 'width': 100},
    'EventData_ClientAddress': {'label': '客户端地址', 'group': '网络信息', 'width': 160},
    'EventData_ClientIP': {'label': '客户端IP', 'group': '网络信息', 'width': 140},
}

# ==================== 合并所有字段 ====================
FIELD_DICT = {}
FIELD_DICT.update(BASE_FIELDS)
FIELD_DICT.update(SECURITY_FIELDS)
FIELD_DICT.update(SYSTEM_FIELDS)
FIELD_DICT.update(APPLICATION_FIELDS)
FIELD_DICT.update(POWERSHELL_FIELDS)
FIELD_DICT.update(TERMINAL_SERVICES_FIELDS)

# Fields by log type
FIELDS_BY_LOG_TYPE = {
    'Security': set(BASE_FIELDS.keys()) | set(SECURITY_FIELDS.keys()),
    'System': set(BASE_FIELDS.keys()) | set(SYSTEM_FIELDS.keys()),
    'Application': set(BASE_FIELDS.keys()) | set(APPLICATION_FIELDS.keys()),
    'PowerShell': set(BASE_FIELDS.keys()) | set(POWERSHELL_FIELDS.keys()),
    'TerminalServices': set(BASE_FIELDS.keys()) | set(TERMINAL_SERVICES_FIELDS.keys()),
}


# ==================== 辅助函数 ====================

def get_log_type_by_channel(channel: str) -> str:
    """通过Channel获取日志类型"""
    if not channel:
        return 'Unknown'
    return CHANNEL_TO_LOG_TYPE.get(channel, 'Unknown')


def is_supported_channel(channel: str) -> bool:
    """Check if Channel is supported - All channels are now supported"""
    return True  # All log types are supported


def get_field_info(field_name: str) -> dict:
    """获取字段信息"""
    return FIELD_DICT.get(field_name, {
        'label': field_name,
        'group': '其他',
        'width': 120,
    })


def get_all_fields() -> dict:
    """获取所有字段"""
    return FIELD_DICT.copy()


def get_fields_for_log_type(log_type: str) -> set:
    """获取指定日志类型的字段集合"""
    return FIELDS_BY_LOG_TYPE.get(log_type, set(BASE_FIELDS.keys()))


def get_default_visible_fields() -> list:
    """获取默认显示字段"""
    return DEFAULT_VISIBLE_FIELDS.copy()


def get_recommended_fields(log_type: str) -> list:
    """获取推荐显示字段"""
    return RECOMMENDED_FIELDS_BY_TYPE.get(log_type, DEFAULT_VISIBLE_FIELDS).copy()
