from pathlib import Path
import tomllib
import msgspec

from src.models.sys.config import ProjectConfig


def load_project_config(
    raw_settings: dict[str, object] | ProjectConfig | None,
    *,
    base_dir: str | Path = ".",
) -> ProjectConfig:
    """从已解析的配置映射构建 ProjectConfig。"""

    if raw_settings is None:
        cfg = ProjectConfig()
    elif isinstance(raw_settings, ProjectConfig):
        cfg = raw_settings
    else:
        cfg = msgspec.convert(raw_settings, type=ProjectConfig, strict=False)

    if cfg.runtime is not None:
        cfg.runtime = cfg.runtime.normalized()
    if cfg.auth is not None:
        cfg.auth = cfg.auth.normalized()
    if cfg.auth_control is not None:
        default_module = (
            cfg.runtime.service_name if cfg.runtime is not None else "data_worker"
        )
        cfg.auth_control = cfg.auth_control.normalized(default_module)
    if cfg.milvus is not None:
        cfg.milvus = cfg.milvus.normalized()
    if cfg.inference is None:
        raise ValueError("inference config is required for data_worker startup")
    cfg.inference = cfg.inference.normalized(base_dir=base_dir)
    if cfg.agent is not None:
        cfg.agent = cfg.agent.normalized()
    return cfg


def load_project_config_from_toml(
    settings_path: str = "settings.toml",
) -> ProjectConfig:
    """从 TOML 文件读取并构建 ProjectConfig。"""

    path = Path(settings_path).expanduser()
    if not path.exists():
        return load_project_config({}, base_dir=path.parent)

    with path.open("rb") as f:
        raw = tomllib.load(f)
    return load_project_config(raw, base_dir=path.parent)






