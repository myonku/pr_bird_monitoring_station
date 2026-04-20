from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import date, datetime, time, timedelta
from uuid import UUID, uuid4

from src.iface.business.data_server_svc import IDataServerService
from src.iface.business.device_entity_svc import IDeviceEntityManager
from src.iface.business.envelope_svc import IEnvelopeManager
from src.iface.business.monitoring_record_svc import IMonitoringRecordManager
from src.iface.business.species_profile_svc import ISpeciesProfileManager
from src.iface.business.user_entity_svc import IUserEntityManager
from src.iface.business.user_profile_svc import IUserProfileManager
from src.models.business.client_req_dto import *
from src.models.business.client_resp_dto import *
from src.models.business.data import MonitoringRecord, UserProfile
from src.models.common.entities import DeviceEntity, UserEntity
from src.utils.crypto_utils import CryptoUtils


class DataServerService(IDataServerService):
    """数据服务器的业务服务实现，负责协调各个领域的管理器。"""

    def __init__(
        self,
        *,
        user_profile_manager: IUserProfileManager,
        user_entity_manager: IUserEntityManager,
        device_entity_manager: IDeviceEntityManager,
        species_profile_manager: ISpeciesProfileManager,
        record_manager: IMonitoringRecordManager,
        envelope_manager: IEnvelopeManager,
    ) -> None:
        if user_profile_manager is None:
            raise ValueError("user profile manager is required")
        if user_entity_manager is None:
            raise ValueError("user entity manager is required")
        if device_entity_manager is None:
            raise ValueError("device entity manager is required")
        if species_profile_manager is None:
            raise ValueError("species profile manager is required")
        if record_manager is None:
            raise ValueError("record manager is required")
        if envelope_manager is None:
            raise ValueError("envelope manager is required")
        self._user_profile_manager = user_profile_manager
        self._user_entity_manager = user_entity_manager
        self._device_entity_manager = device_entity_manager
        self._species_profile_manager = species_profile_manager
        self._record_manager = record_manager
        self._envelope_manager = envelope_manager

    async def get_user_profile(
        self,
        request: ClientUserProfileRequest,
    ) -> ClientUserProfileResponse | None:
        """查询用户资料。"""
        identifier = self._normalize_text(request.identifier)
        if not identifier:
            raise ValueError("identifier is required")

        profiles = await self._user_profile_manager.list_all()
        profile = self._find_profile_by_identifier(profiles, identifier)
        if profile is None:
            return None
        return self._profile_to_response(profile)

    async def register_user(
        self,
        request: ClientRegisterRequest,
    ) -> ClientRegisterResponse:
        """注册新用户。"""
        normalized_username = self._normalize_username(request.username)
        display_name = self._display_text(request.username)
        password = self._normalize_text(request.password)
        normalized_email = self._normalize_email(request.email)
        raw_phone = self._normalize_text(request.phone)
        normalized_phone = self._normalize_phone(raw_phone)

        if not normalized_username or len(password) < 6:
            return ClientRegisterResponse(
                ok=False,
                error_code="invalid_data",
                message="注册信息不完整",
            )

        try:
            profiles = await self._user_profile_manager.list_all()
        except Exception:
            return ClientRegisterResponse(
                ok=False,
                error_code="data_error",
                message="注册数据异常，请稍后重试",
            )

        duplicate_error = self._find_registration_conflict(
            profiles,
            username=normalized_username,
            email=normalized_email,
            phone=normalized_phone,
        )
        if duplicate_error is not None:
            return duplicate_error

        try:
            hash_algorithm, password_hash = CryptoUtils.hash_password(password)
        except ValueError:
            return ClientRegisterResponse(
                ok=False,
                error_code="data_error",
                message="注册数据异常，请稍后重试",
            )
        except Exception:
            return ClientRegisterResponse(
                ok=False,
                error_code="unknown_error",
                message="注册失败，请稍后重试",
            )

        now_ms = DataServerService._now_ms()

        profile = UserProfile(
            _id=uuid4(),
            username=normalized_username,
            display_name=display_name or normalized_username,
            email=normalized_email,
            phone=raw_phone,
            role="注册用户",
            avatar_b64="",
            metadata={},
        )

        try:
            created_profile = await self._user_profile_manager.create(profile)
        except ValueError:
            return ClientRegisterResponse(
                ok=False,
                error_code="invalid_data",
                message="注册信息不完整",
            )
        except Exception:
            return ClientRegisterResponse(
                ok=False,
                error_code="data_error",
                message="注册数据异常，请稍后重试",
            )

        user_entity = UserEntity(
            user_entity_id=uuid4(),
            user_profile_id=created_profile.id,
            user_name=normalized_username,
            role="user",
            password_hash=password_hash,
            hash_algorithm=hash_algorithm,
            email=normalized_email,
            phone=raw_phone,
            status="active",
            created_at_ms=now_ms,
            updated_at_ms=now_ms,
            last_login_at_ms=0,
            password_updated_at_ms=now_ms,
            metadata={},
        )

        try:
            await self._user_entity_manager.insert(user_entity)
        except Exception:
            try:
                await self._user_profile_manager.delete(created_profile.id)
            except Exception:
                pass
            return ClientRegisterResponse(
                ok=False,
                error_code="data_error",
                message="注册数据异常，请稍后重试",
            )

        return ClientRegisterResponse(ok=True, message="注册成功")

    async def count_today_monitoring_records(self) -> int:
        """统计今天的监测记录数。"""
        today = self._today_local()
        records = await self._record_manager.list_all()
        return sum(
            1
            for record in records
            if self._is_same_local_day(record.captured_at_ms, today)
        )

    async def count_today_upload_records(self) -> int:
        """统计今天的上传记录数。"""
        today = self._today_local()
        envelopes = await self._envelope_manager.list_all()
        return sum(
            1
            for envelope in envelopes
            if self._is_same_local_day(envelope.received_at_ms, today)
        )

    async def count_online_stations(self) -> int:
        """统计在线的站点数。"""
        devices = await self._device_entity_manager.list_all()
        return len(devices)

    async def get_today_top_upload_station(self) -> ClientUploadStationSummaryResponse:
        """获取今天上传最活跃的站点摘要。"""
        today = self._today_local()
        envelopes = await self._envelope_manager.list_all()
        today_uploads = [
            envelope
            for envelope in envelopes
            if self._is_same_local_day(envelope.received_at_ms, today)
        ]
        if not today_uploads:
            return ClientUploadStationSummaryResponse(
                device_id="",
                device_name="暂无数据",
                upload_count=0,
            )

        counts: Counter[str] = Counter()
        names: dict[str, str] = {}
        for envelope in today_uploads:
            device_id = str(envelope.device_entity_id)
            counts[device_id] += 1
            names.setdefault(
                device_id,
                self._display_text(envelope.device_name, fallback=device_id),
            )

        top_device_id, top_count = max(
            counts.items(), key=lambda item: (item[1], item[0])
        )
        return ClientUploadStationSummaryResponse(
            device_id=top_device_id,
            device_name=names.get(top_device_id, top_device_id),
            upload_count=top_count,
        )

    async def get_latest_upload_summary(self) -> ClientLatestUploadSummaryResponse:
        """获取最近上传的站点和时间摘要。"""
        envelopes = await self._envelope_manager.list_all()
        if not envelopes:
            return ClientLatestUploadSummaryResponse(
                device_id="",
                device_name="-",
                uploaded_at_ms=None,
                uploaded_at_label="-",
            )

        latest = max(envelopes, key=lambda item: (item.received_at_ms, str(item.id)))
        device_name = self._display_text(
            latest.device_name, fallback=str(latest.device_entity_id)
        )
        return ClientLatestUploadSummaryResponse(
            device_id=str(latest.device_entity_id),
            device_name=device_name,
            uploaded_at_ms=latest.received_at_ms,
            uploaded_at_label=self._format_local_ms(latest.received_at_ms),
        )

    async def list_recent_records(
        self, limit: int = 3
    ) -> list[ClientBirdRecordResponse]:
        """获取首页最近的监测记录摘要列表。默认为最近 3 条记录。"""
        records = await self._record_manager.list_all()
        sorted_records = sorted(
            records,
            key=self._record_sort_key,
            reverse=True,
        )
        return await self._records_to_client_responses(
            sorted_records[: max(int(limit), 0)]
        )

    async def get_dashboard_snapshot(
        self,
        request: ClientHomeSnapshotRequest | None = None,
    ) -> ClientDashboardSnapshotResponse:
        """获取首页概览数据。该接口为聚合接口，内部调用多个管理器方法组合得到结果，用于减少客户端并发请求数。"""

        _ = (
            request.device_id if request is not None else None
        )  # 目前请求参数未使用，预留后续按站点过滤的能力
        devices = await self._device_entity_manager.list_all()
        records = await self._record_manager.list_all()
        envelopes = await self._envelope_manager.list_all()

        today = self._today_local()
        today_monitoring_count = sum(
            1
            for record in records
            if self._is_same_local_day(record.captured_at_ms, today)
        )
        today_upload_count = sum(
            1
            for envelope in envelopes
            if self._is_same_local_day(envelope.received_at_ms, today)
        )
        active_station_count = len(
            {
                str(record.device_entity_id)
                for record in records
                if str(record.device_entity_id).strip()
            }
        )

        recent_records = await self._records_to_client_responses(
            sorted(records, key=self._record_sort_key, reverse=True)[:3]
        )

        return ClientDashboardSnapshotResponse(
            today_recognition_count=today_monitoring_count,
            today_upload_count=today_upload_count,
            online_station_count=len(devices),
            active_station_count=active_station_count,
            top_upload_station=await self.get_today_top_upload_station(),
            latest_upload=await self.get_latest_upload_summary(),
            recent_records=recent_records,
        )

    async def list_record_station_options(
        self,
        request: ClientRecordStationOptionsRequest | None = None,
    ) -> list[ClientRecordStationOptionResponse]:
        """列出记录页/统计页的站点筛选选项。返回可用于下拉框展示的站点 ID、站点名和在线状态。"""
        devices = await self._device_entity_manager.list_all()
        include_offline = None if request is None else request.include_offline

        sorted_devices = sorted(
            devices,
            key=lambda item: (
                self._display_text(
                    item.device_name, fallback=str(item.device_entity_id)
                ).casefold(),
                str(item.device_entity_id),
            ),
        )

        result: list[ClientRecordStationOptionResponse] = []
        for device in sorted_devices:
            online = self._device_is_online(device)
            if include_offline is False and not online:
                continue
            result.append(
                ClientRecordStationOptionResponse(
                    device_id=str(device.device_entity_id),
                    device_name=self._display_text(
                        device.device_name, fallback=str(device.device_entity_id)
                    ),
                    online=online,
                    status=self._normalize_device_status(device.status),
                )
            )
        return result

    async def list_records_by_cursor(
        self,
        request: ClientRecordsCursorRequest,
    ) -> ClientRecordsCursorResponse:
        """基于游标分页的监测记录查询接口。支持按时间范围、站点、关键词和置信度过滤。
        返回符合条件的记录列表，以及下一页的游标和是否有更多数据的标志。"""

        start_day, end_day = self._resolve_day_range(
            request.start_at_ms,
            request.end_at_ms,
            default_days=7,
        )
        records = await self._record_manager.list_all()
        filtered = self._filter_records(
            records,
            start_day=start_day,
            end_day=end_day,
            device_id=request.device_id,
            keyword=request.keyword,
            confidence_min=request.confidence_min,
        )
        sorted_records = sorted(filtered, key=self._record_sort_key, reverse=True)

        cursor_index = self._parse_cursor(request.cursor)
        limit = request.limit if request.limit > 0 else 20
        if limit > 100:
            limit = 100
        page_items = sorted_records[cursor_index : cursor_index + limit]
        next_cursor_index = cursor_index + len(page_items)

        items = await self._records_to_client_responses(page_items)
        return ClientRecordsCursorResponse(
            items=items,
            next_cursor=(
                str(next_cursor_index)
                if next_cursor_index < len(sorted_records)
                else ""
            ),
            has_more=next_cursor_index < len(sorted_records),
        )

    async def get_weekly_trend(
        self,
        request: ClientWeeklyTrendRequest,
    ) -> ClientWeeklyTrendResponse:
        """获取最近一周的监测记录趋势数据。返回每天的记录数量，以及总记录数。"""

        days = request.days if request.days > 0 else 7
        today = self._today_local()
        start_day = today - timedelta(days=days - 1)
        end_day = today

        records = await self._record_manager.list_all()
        filtered_records = self._filter_records(
            records,
            start_day=start_day,
            end_day=end_day,
            device_id=request.device_id,
            keyword=None,
            confidence_min=None,
        )

        counts_by_day: dict[date, int] = {}
        for record in filtered_records:
            record_day = self._local_date_from_ms(record.captured_at_ms)
            counts_by_day[record_day] = counts_by_day.get(record_day, 0) + 1

        series: list[ClientTrendPointResponse] = []
        current_day = start_day
        while current_day <= end_day:
            series.append(
                ClientTrendPointResponse(
                    label=self._weekday_label(current_day),
                    value=counts_by_day.get(current_day, 0),
                    date_ms=self._local_day_start_ms(current_day),
                )
            )
            current_day = current_day + timedelta(days=1)

        return ClientWeeklyTrendResponse(
            series=series,
            total=sum(point.value for point in series),
        )

    async def get_range_summary(
        self,
        request: ClientRangeSummaryRequest,
    ) -> ClientRangeSummaryResponse:
        """获取指定时间范围内的监测记录摘要数据。返回总记录数、每天的记录数量分布、物种占比、峰值日期和峰值站点等信息。"""

        start_day, end_day = self._resolve_day_range(
            request.start_at_ms,
            request.end_at_ms,
            default_days=7,
        )
        if end_day < start_day:
            raise ValueError("end_at_ms must be greater than or equal to start_at_ms")
        if (end_day - start_day).days + 1 > 30:
            raise ValueError("time range cannot exceed 30 days")

        records = await self._record_manager.list_all()
        filtered_records = self._filter_records(
            records,
            start_day=start_day,
            end_day=end_day,
            device_id=request.device_id,
            keyword=None,
            confidence_min=None,
        )

        daily_distribution: list[ClientTrendPointResponse] = []
        counts_by_day: dict[date, int] = {}
        for record in filtered_records:
            record_day = self._local_date_from_ms(record.captured_at_ms)
            counts_by_day[record_day] = counts_by_day.get(record_day, 0) + 1

        current_day = start_day
        while current_day <= end_day:
            daily_distribution.append(
                ClientTrendPointResponse(
                    label=f"{current_day.month}/{current_day.day}",
                    value=counts_by_day.get(current_day, 0),
                    date_ms=self._local_day_start_ms(current_day),
                )
            )
            current_day = current_day + timedelta(days=1)

        if daily_distribution:
            peak_point = max(
                daily_distribution,
                key=lambda item: (item.value, -self._safe_day_index(item.date_ms)),
            )
            peak_day = ClientPeakDayResponse(
                label=peak_point.label,
                value=peak_point.value,
                date_ms=peak_point.date_ms,
            )
        else:
            peak_day = ClientPeakDayResponse(label="-", value=0, date_ms=None)

        species_counts: Counter[str] = Counter()
        species_entity_ids: dict[str, str] = {}
        for record in filtered_records:
            species_label = self._display_text(
                record.species_name, fallback=record.scientific_name
            )
            if not species_label:
                species_label = "-"
            species_counts[species_label] += 1
            if record.species_entity_id is not None:
                species_entity_ids.setdefault(
                    species_label, str(record.species_entity_id)
                )

        species_shares = [
            ClientSpeciesShareResponse(
                label=species_label,
                value=count,
                ratio=(count / len(filtered_records)) if filtered_records else 0.0,
                species_entity_id=species_entity_ids.get(species_label, ""),
                color_hex=self._species_color_hex(species_label),
            )
            for species_label, count in sorted(
                species_counts.items(), key=lambda item: (-item[1], item[0])
            )
        ]

        peak_device = self._build_peak_device_summary(filtered_records)

        return ClientRangeSummaryResponse(
            total_count=len(filtered_records),
            daily_distribution=daily_distribution,
            species_shares=species_shares,
            peak_day=peak_day,
            peak_device=peak_device,
        )

    @staticmethod
    def _record_sort_key(record: MonitoringRecord) -> tuple[int, str]:
        return (int(record.captured_at_ms), str(record.id))

    @staticmethod
    def _normalize_text(value: str | None) -> str:
        return (value or "").strip()

    @staticmethod
    def _normalize_username(value: str | None) -> str:
        return DataServerService._normalize_text(value).casefold()

    @staticmethod
    def _normalize_email(value: str | None) -> str:
        return DataServerService._normalize_text(value).casefold()

    @staticmethod
    def _normalize_phone(value: str | None) -> str:
        return re.sub(r"\D", "", DataServerService._normalize_text(value))

    @staticmethod
    def _display_text(value: str | None, fallback: str = "") -> str:
        text = DataServerService._normalize_text(value)
        if not text or text.casefold() == "unknown":
            return fallback
        return text

    @staticmethod
    def _normalize_device_status(value: str | None) -> str:
        normalized = DataServerService._normalize_text(value).casefold()
        if normalized in {"online", "offline", "error", "unknown"}:
            return normalized
        return "unknown"

    @staticmethod
    def _device_is_online(device: DeviceEntity) -> bool:
        return DataServerService._normalize_device_status(device.status) == "online"

    @staticmethod
    def _today_local() -> date:
        return datetime.now().date()

    @staticmethod
    def _local_date_from_ms(milliseconds: int) -> date:
        return datetime.fromtimestamp(max(int(milliseconds), 0) / 1000.0).date()

    @staticmethod
    def _local_day_start_ms(day: date) -> int:
        return int(datetime.combine(day, time.min).timestamp() * 1000)

    @staticmethod
    def _format_local_ms(milliseconds: int) -> str:
        value = datetime.fromtimestamp(max(int(milliseconds), 0) / 1000.0)
        return (
            f"{value.year:04d}-{value.month:02d}-{value.day:02d} "
            f"{value.hour:02d}:{value.minute:02d}"
        )

    @staticmethod
    def _is_same_local_day(milliseconds: int, day: date) -> bool:
        return DataServerService._local_date_from_ms(milliseconds) == day

    @staticmethod
    def _resolve_day_range(
        start_at_ms: int | None,
        end_at_ms: int | None,
        *,
        default_days: int,
    ) -> tuple[date, date]:
        start_value = int(start_at_ms or 0)
        end_value = int(end_at_ms or 0)
        if start_value == 0 and end_value == 0:
            end_day = DataServerService._today_local()
            start_day = end_day - timedelta(days=default_days - 1)
            return start_day, end_day
        return (
            DataServerService._local_date_from_ms(start_value),
            DataServerService._local_date_from_ms(end_value),
        )

    @staticmethod
    def _weekday_label(day: date) -> str:
        return {
            0: "周一",
            1: "周二",
            2: "周三",
            3: "周四",
            4: "周五",
            5: "周六",
            6: "周日",
        }.get(day.weekday(), "未知")

    @staticmethod
    def _species_color_hex(label: str) -> str:
        palette = ("#0B7A75", "#125D98", "#C97C1D", "#6D597A", "#2A9D8F", "#E76F51")
        digest = hashlib.sha256(label.encode("utf-8")).digest()
        return palette[digest[0] % len(palette)]

    @staticmethod
    def _safe_day_index(milliseconds: int | None) -> int:
        if milliseconds is None:
            return 0
        return milliseconds

    @staticmethod
    def _now_ms() -> int:
        return int(datetime.now().timestamp() * 1000)

    @staticmethod
    def _parse_cursor(cursor: str | None) -> int:
        normalized = DataServerService._normalize_text(cursor)
        if not normalized:
            return 0
        try:
            value = int(normalized)
        except ValueError:
            return 0
        return value if value >= 0 else 0

    async def _records_to_client_responses(
        self,
        records: list[MonitoringRecord],
    ) -> list[ClientBirdRecordResponse]:
        return [self._record_to_response(record) for record in records]

    def _record_to_response(self, record: MonitoringRecord) -> ClientBirdRecordResponse:
        species_label = self._display_text(
            record.species_name, fallback=record.scientific_name
        )
        if not species_label:
            species_label = ""
        scientific_name = self._display_text(record.scientific_name)
        device_name = self._display_text(
            record.device_name, fallback=str(record.device_entity_id)
        )
        species_entity_id = (
            str(record.species_entity_id)
            if record.species_entity_id is not None
            else ""
        )

        return ClientBirdRecordResponse(
            id=str(record.id),
            species=species_label,
            scientific_name=scientific_name,
            captured_at_ms=record.captured_at_ms,
            captured_at_label=self._format_local_ms(record.captured_at_ms),
            device_id=str(record.device_entity_id),
            device_name=device_name,
            confidence=record.confidence,
            temperature_c=record.temperature_c,
            humidity_pct=record.humidity_pct,
            upload_summary=record.summary_text,
            species_intro=record.species_intro,
            image_b64=record.image_b64,
            media_refs=list(record.media_refs or []),
            processing_source=record.processing_source,
            model_version=record.model_version,
            record_status=record.record_status,
            summary_text=record.summary_text,
            species_entity_id=species_entity_id,
            metadata=dict(record.metadata or {}),
        )

    def _profile_to_response(self, profile: UserProfile) -> ClientUserProfileResponse:
        display_name = self._display_text(
            profile.display_name, fallback=profile.username
        )
        if not display_name:
            display_name = profile.username
        return ClientUserProfileResponse(
            user_id=str(profile.id),
            username=profile.username,
            display_name=display_name,
            name=display_name,
            role=profile.role,
            email=profile.email,
            phone=profile.phone,
            avatar_b64=profile.avatar_b64,
        )

    def _find_profile_by_identifier(
        self,
        profiles: list[UserProfile],
        identifier: str,
    ) -> UserProfile | None:
        search_order = self._identifier_search_order(identifier)
        for field_name in search_order:
            for profile in profiles:
                if self._profile_matches_identifier(profile, identifier, field_name):
                    return profile
        return None

    def _find_registration_conflict(
        self,
        profiles: list[UserProfile],
        *,
        username: str,
        email: str,
        phone: str,
    ) -> ClientRegisterResponse | None:
        for profile in profiles:
            if self._normalize_username(profile.username) == username:
                return ClientRegisterResponse(
                    ok=False,
                    error_code="username_exists",
                    message="用户名已存在",
                )

        if email:
            for profile in profiles:
                if self._normalize_email(profile.email) == email:
                    return ClientRegisterResponse(
                        ok=False,
                        error_code="email_exists",
                        message="邮箱已存在",
                    )

        if phone:
            for profile in profiles:
                if self._normalize_phone(profile.phone) == phone:
                    return ClientRegisterResponse(
                        ok=False,
                        error_code="phone_exists",
                        message="手机号已存在",
                    )

        return None

    @staticmethod
    def _identifier_search_order(identifier: str) -> tuple[str, str, str]:
        normalized = DataServerService._normalize_text(identifier)
        if "@" in normalized:
            return ("email", "username", "phone")

        phone_digits = DataServerService._normalize_phone(normalized)
        if phone_digits and phone_digits == re.sub(r"\D", "", normalized):
            return ("phone", "username", "email")

        return ("username", "email", "phone")

    def _profile_matches_identifier(
        self,
        profile: UserProfile,
        identifier: str,
        field_name: str,
    ) -> bool:
        normalized_identifier = self._normalize_text(identifier)
        if field_name == "username":
            return (
                self._normalize_username(profile.username)
                == normalized_identifier.casefold()
            )
        if field_name == "email":
            return (
                self._normalize_email(profile.email) == normalized_identifier.casefold()
            )
        if field_name == "phone":
            phone = self._normalize_phone(identifier)
            return bool(phone) and self._normalize_phone(profile.phone) == phone
        return False

    def _filter_records(
        self,
        records: list[MonitoringRecord],
        *,
        start_day: date,
        end_day: date,
        device_id: str | None,
        keyword: str | None,
        confidence_min: float | None,
    ) -> list[MonitoringRecord]:
        if end_day < start_day:
            raise ValueError("end_at_ms must be greater than or equal to start_at_ms")

        device_filter = self._normalize_text(device_id)
        keyword_filter = self._normalize_text(keyword).casefold()

        if device_filter:
            try:
                UUID(device_filter)
            except ValueError as exc:
                raise ValueError("device_id is invalid") from exc

        if confidence_min is not None:
            if not 0.0 <= float(confidence_min) <= 1.0:
                raise ValueError("confidence_min must be between 0 and 1")
            confidence_threshold = float(confidence_min)
        else:
            confidence_threshold = None

        start_ms = self._local_day_start_ms(start_day)
        end_ms = self._local_day_start_ms(end_day + timedelta(days=1))

        filtered: list[MonitoringRecord] = []
        for record in records:
            if record.captured_at_ms < start_ms or record.captured_at_ms >= end_ms:
                continue
            if device_filter and str(record.device_entity_id) != device_filter:
                continue
            if (
                confidence_threshold is not None
                and record.confidence < confidence_threshold
            ):
                continue
            if keyword_filter:
                haystack = " ".join(
                    [
                        record.species_name,
                        record.scientific_name,
                        record.summary_text,
                        record.species_intro,
                        record.device_name,
                    ]
                ).casefold()
                if keyword_filter not in haystack:
                    continue
            filtered.append(record)
        return filtered

    def _build_peak_device_summary(
        self,
        records: list[MonitoringRecord],
    ) -> ClientPeakDeviceSummaryResponse:
        if not records:
            return ClientPeakDeviceSummaryResponse(
                device_id="",
                device_name="-",
                record_count=0,
            )

        counts: Counter[str] = Counter()
        names: dict[str, str] = {}
        for record in records:
            device_id = str(record.device_entity_id)
            counts[device_id] += 1
            names.setdefault(
                device_id, self._display_text(record.device_name, fallback=device_id)
            )

        peak_device_id, peak_count = max(
            counts.items(), key=lambda item: (item[1], item[0])
        )
        return ClientPeakDeviceSummaryResponse(
            device_id=peak_device_id,
            device_name=names.get(peak_device_id, peak_device_id),
            record_count=peak_count,
        )
