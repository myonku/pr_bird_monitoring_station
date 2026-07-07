from typing import Any

MONGO_VIEWS: dict[str, dict[str, Any]] = {
    "monitoring_records": {
        "description": "监测记录：每次识别成功后落库的观测记录",
        "fields": {
            "species_name": "鸟种中文名，如'白颊噪鹛'、'大山雀'",
            "scientific_name": "学名，如'Pterorhinus sannio'",
            "device_name": "观测设备/站点名称",
            "captured_at_ms": "观测时间戳（毫秒）",
            "confidence": "识别置信度，范围 0~1",
            "temperature_c": "温度（摄氏度），可能为空",
            "humidity_pct": "湿度（百分比），可能为空",
            "processing_source": "处理来源，'edge' 或 'data_worker'",
            "summary_text": "推理摘要文本",
        },
        "filterable_fields": [
            "species_name",
            "scientific_name",
            "device_name",
            "captured_at_ms",
            "confidence",
            "processing_source",
        ],
        "sortable_fields": ["captured_at_ms", "confidence"],
        "time_field": "captured_at_ms",
    },
    "edge_event_envelopes": {
        "description": "边缘端上传事件：每次边缘设备上报的原始记录，无论是否识别成功",
        "fields": {
            "device_name": "设备名称",
            "occurred_at_ms": "事件发生时间（毫秒）",
            "received_at_ms": "服务器接收时间（毫秒）",
            "payload_type": "载荷类型：image/video/audio/metadata/mixed",
        },
        "filterable_fields": ["device_name", "payload_type", "occurred_at_ms"],
        "sortable_fields": ["occurred_at_ms", "received_at_ms"],
        "time_field": "occurred_at_ms",
    },
}


MYSQL_VIEWS: dict[str, dict[str, Any]] = {
    "device_entities": {
        "description": "设备列表：注册的边缘观测设备",
        "fields": {
            "device_name": "设备名称",
            "location_name": "设备位置/地点名",
            "status": "设备状态：online/offline/error/unknown",
            "latitude": "纬度",
            "longitude": "经度",
        },
        "filterable_fields": ["device_name", "location_name", "status"],
    },
    "species_profiles": {
        "description": "鸟种简介：每种鸟的简要信息（非百科，仅基础描述）",
        "fields": {
            "species_name": "鸟种中文名",
            "scientific_name": "学名",
            "label_name": "英文标签名",
            "intro": "简介文本",
            "habitat": "栖息地描述",
            "protection_level": "保护级别",
        },
        "filterable_fields": [
            "species_name",
            "scientific_name",
            "label_name",
        ],
    },
}

AGGREGATION_HELP = """
支持以下聚合操作：
- count: 计数
- count_distinct(field): 某字段去重计数
- avg(field): 平均值
- min(field): 最小值
- max(field): 最大值
- group_by(field): 按某字段分组，常与 count/avg 等联用
- top(field, N): 按 field 排序取前 N 条
"""

ALLOWED_COLLECTIONS = list(MONGO_VIEWS.keys())
ALLOWED_TABLES = list(MYSQL_VIEWS.keys())


def build_schema_prompt() -> str:
    """生成供 LLM 使用的 schema 描述文本。"""
    lines = ["## 可查询的数据源\n"]

    lines.append("### MongoDB 集合\n")
    for name, view in MONGO_VIEWS.items():
        lines.append(f"**{name}**：{view['description']}")
        lines.append("字段：")
        for fname, fdesc in view["fields"].items():
            lines.append(f"  - `{fname}`：{fdesc}")
        lines.append("")

    lines.append("### MySQL 表\n")
    for name, view in MYSQL_VIEWS.items():
        lines.append(f"**{name}**：{view['description']}")
        lines.append("字段：")
        for fname, fdesc in view["fields"].items():
            lines.append(f"  - `{fname}`：{fdesc}")
        lines.append("")

    lines.append("### 聚合操作\n")
    lines.append(AGGREGATION_HELP.strip())
    lines.append("")

    lines.append("### 查询格式\n")
    lines.append("""返回 JSON 格式的查询描述，不要包含多余解释。示例如下：

简单查询：
{"source": "mongo", "collection": "monitoring_records", "filter": {"species_name": "白颊噪鹛"}, "sort": {"captured_at_ms": -1}, "limit": 10}

聚合查询：
{"source": "mongo", "collection": "monitoring_records", "aggregate": [{"$group": {"_id": "$species_name", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 10}]}

MySQL 查询：
{"source": "mysql", "table": "species_profiles", "filter": {"label_name": "great_tit"}, "limit": 5}

统计总数：
{"source": "mongo", "collection": "edge_event_envelopes", "aggregate": [{"$count": "total"}]}
""")
    return "\n".join(lines)
