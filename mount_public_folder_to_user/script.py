import configparser
import json
import logging
from logging.handlers import RotatingFileHandler
import sys
import time
from typing import Dict, Any, List, Literal, Tuple, Set, Optional
from dataclasses import dataclass
import grp
import pwd
import subprocess
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


##############################################
# 日志
LOG_FILE = Path(__file__).parent / "mount_manager.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.handlers.RotatingFileHandler(LOG_FILE, encoding='utf-8', mode='a', maxBytes=500 * 1024),
        logging.StreamHandler(sys.stdout),  # 保留打印到控制台
    ]
)
logger = logging.getLogger(__name__)

##############################################
# 挂载记录

RECORD_FILE = Path(__file__).parent / 'mount_manager.json'

def load_mounted_records() -> Set[Tuple[str, str]]:
    try:
        with open(RECORD_FILE, 'r', encoding='utf-8') as f:
            mounted_record_dicts: List[Dict[str, str]] = json.load(f)
            mounted_records = [
                (record['src_path'], record['dst_path'])
                for record in mounted_record_dicts
            ]
        return set(mounted_records)
    except Exception as e:
        logger.warning(f'无法加载挂载记录: {e}')
        return set()

def save_mounted_records(current_targets: Set[Tuple[str, str]]):
    current_targets_dicts = [
        {
            'src_path': src,
            'dst_path': dst
        }
        for src, dst in current_targets
    ]
    with open(RECORD_FILE, 'w', encoding='utf-8') as f:
        json.dump(current_targets_dicts, f, ensure_ascii=True, indent=2)

def is_empty_dir(path: Path) -> bool:
    try:
        return path.is_dir() and not any(path.iterdir())
    except Exception as e:
        logger.error(f"检查目录 {path} 是否为空时出错: {e}")
        return False

def remove_dir_if_empty(path: Path):
    if is_empty_dir(path):
        try:
            path.rmdir()
            logger.info(f"已删除空目录：{path}")
            return True
        except Exception as e:
            logger.error(f"删除目录 {path} 失败: {e}")
            return False
    else:
        return False


def unmount_obsolete_mounts(config_targets: Set[Tuple[str, str]]):
    mounted_records: Set[Tuple[str, str]] = load_mounted_records()
    obsolete = mounted_records - config_targets

    for src, dst in obsolete:
        dst_path = Path(dst)

        # 先检查是否真的还是挂载点
        if not is_mount_point(dst_path):
            logger.info(f"{dst} 已经不是挂载点，跳过卸载")
            # 尝试删除空目录
            remove_dir_if_empty(dst_path)
            continue

        try:
            subprocess.run(['umount', dst], check=True)
            logger.info(f"卸载过期挂载：{dst}")
            if not remove_dir_if_empty(dst_path):
                raise
        except Exception as e:
            logger.error(f"卸载 {dst} 失败，使用 Lazy 模式重试中：{e}")
            try:
                subprocess.run(['umount', '-l', dst], check=True)
                logger.info(f"Lazy 模式卸载 {dst} 成功，开始检测是否可删除目录")
                for i in range(5):
                    time.sleep(1)  # 等待系统完成卸载
                    if not is_mount_point(dst_path):
                        if remove_dir_if_empty(dst_path):
                            break
                        else:
                            logger.warning(f"目录 {dst} 尝试 {i + 1} 次仍未变为空，未删除。")
                    else:
                        logger.warning(f"挂载点 {dst} 尝试 {i + 1} 次仍未完全卸载")
            except Exception as e2:
                logger.error(f"Lazy 模式卸载 {dst} 也失败：{e2}")


###############################################
# 配置解析


CFG_FILE = Path(__file__).parent / "config.ini"

VALID_TYPES = ['远程挂载', '外接存储', '本地存储']
VALID_CONFLICTS = ['跳过', '覆盖', '重命名']

@dataclass
class MountConfig:
    type: Literal['远程挂载', '外接存储', '本地存储']
    src: str
    dst: str
    groups: List[str]
    conflict: Literal['跳过', '覆盖', '重命名']

def next_config(config):

    for section in config.sections():
        conf: Dict[str, Any] = dict(config.items(section))
        try:
            yield MountConfig(
                type=conf['type'],
                src=conf['src'],
                dst=conf['dst'],
                groups=[g.strip() for g in conf['groups'].split(',')],
                conflict=conf['conflict']
            )
        except KeyError as e:
            logger.warning(f'配置项 {e} 缺失，忽略该挂载项')
            continue


################################################
# 工具函数

def is_mount_point(path: Path) -> bool:
    """
    检查路径是否为挂载点
    """
    try:
        return path.is_mount()
    except Exception as e:
        logger.error(f"检查挂载点 {path} 时出错: {e}")
        return False

def get_mount_source(mount_point: Path) -> Optional[str]:
    """
    获取挂载点的源路径
    通过解析 /proc/mounts 或使用 findmnt 命令
    """
    try:
        # 方法1: 使用 findmnt 命令（更可靠）
        result = subprocess.run(
            ['findmnt', '-n', '-o', 'SOURCE', str(mount_point)],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        # 方法2: 解析 /proc/mounts
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == str(mount_point):
                        return parts[0]
        except Exception as e:
            logger.error(f"读取 /proc/mounts 失败: {e}")
    return None


def handle_existing_mount(src_path: str, dst_path: str) -> bool:
    """
    处理已存在的挂载点
    返回 True 表示需要进行挂载，False 表示跳过
    """
    dst_path_obj = Path(dst_path)

    src_mount_source = get_mount_source(Path(src_path))

    if is_mount_point(dst_path_obj):
        current_source = get_mount_source(dst_path_obj)

        if src_mount_source == current_source or src_mount_source in current_source:
            logger.info(f"挂载点 {dst_path} 已存在且源路径相同，跳过")
            return False
        else:
            logger.info(f"挂载点 {dst_path} 已存在但源路径不同 (当前: {current_source}, 新: {src_mount_source})，先卸载")
            try:
                subprocess.run(['umount', dst_path], check=True)
                logger.info(f"成功卸载旧挂载点: {dst_path}")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"卸载旧挂载点失败: {e}")
                # 尝试 lazy umount
                try:
                    subprocess.run(['umount', '-l', dst_path], check=True)
                    logger.info(f"Lazy 模式卸载旧挂载点成功: {dst_path}")
                    # 等待一下让系统完成卸载
                    time.sleep(0.5)
                    return True
                except subprocess.CalledProcessError as e2:
                    logger.error(f"Lazy 模式卸载也失败: {e2}")
                    return False

    # 不是挂载点，返回 True 继续原有逻辑
    return True


def get_all_mounts() -> Dict[str, str]:
    """
    获取系统中所有的挂载点映射
    返回 {挂载点: 源路径} 的字典
    """
    mounts = {}
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    source, target = parts[0], parts[1]
                    mounts[target] = source
    except Exception as e:
        logger.error(f"读取挂载信息失败: {e}")
    return mounts


def verify_mount_status(config_targets: Set[Tuple[str, str]]):
    """
    验证配置的挂载状态，用于调试
    """
    all_mounts = get_all_mounts()

    for src, dst in config_targets:
        if dst in all_mounts:
            actual_src = all_mounts[dst]
            if actual_src == src:
                logger.debug(f"✓ {dst} 正确挂载到 {src}")
            else:
                logger.warning(f"✗ {dst} 挂载源不匹配: 期望 {src}, 实际 {actual_src}")
        else:
            logger.warning(f"✗ {dst} 未挂载")


def get_uids_in_group(group_name: str) -> List[int]:
    """
    读取指定用户组中的所有用户 uid
    """
    uids = set()
    try:
        # 1. 该组的所有成员（辅助组成员）
        group = grp.getgrnam(group_name)
        for user in group.gr_mem:
            try:
                uids.add(pwd.getpwnam(user).pw_uid)
            except KeyError:
                # 用户不存在，忽略
                pass

        # 2. 该组为主组的所有用户（主组成员）
        gid = group.gr_gid
        for user in pwd.getpwall():
            if user.pw_gid == gid:
                uids.add(user.pw_uid)
    except KeyError:
        logger.error(f"用户组 '{group_name}' 不存在！")
    except PermissionError:
        logger.error(f"权限不足，无法读取用户组 '{group_name}' 的成员！")
    return sorted(uids)

def ensure_dir_and_check_empty(path: Path) -> bool:
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        return True
    elif path.is_dir():
        return not any(path.iterdir())
    else:
        return False

def grant_group_rw_acl(path: Path, group: str, recursive: bool = True):
    """
    给目录 path 授权 group 用户组的 rwX（读写和目录遍历）权限，默认递归。
    :param path: 目标目录
    :param group: 目标用户组名
    :param recursive: 是否递归（类似setfacl -R）
    """
    perms = 'rwX'
    cmd = ['setfacl']
    if recursive:
        cmd.append('-R')
    cmd += ['-m', f'g:{group}:{perms}', str(path)]
    try:
        subprocess.run(cmd, check=True)
        logger.info(f"授予目录 {path} 给组 {group} 权限: {perms}")
    except Exception as e:
        logger.error(f"设置ACL时出错: {e}")

def list_section_mount_targets(section_cfg: MountConfig) -> Set[Tuple[str, str]]:
    section_mount_targets = set()

    # 校验 type 和 conflict
    if section_cfg.type not in VALID_TYPES:
        logger.error(f"类型配置错误: {section_cfg.type}，跳过")
        return section_mount_targets
    if section_cfg.conflict not in VALID_CONFLICTS:
        logger.error(f"冲突配置策略错误: {section_cfg.conflict}，跳过")
        return section_mount_targets
    # 检查src是否存在
    src_path = Path(section_cfg.src)
    if not src_path.exists():
        logger.error(f"源目录 {section_cfg.src} 不存在，跳过")
        return section_mount_targets

    # 检查分组
    valid_groups = []
    valid_uids = []
    for group in section_cfg.groups:
        uids = get_uids_in_group(group)
        if uids:
            valid_groups.append(group)
            valid_uids.extend(uids)
        else:
            logger.error(f"组 {group} 不存在或无用户，跳过")
    if not valid_groups or not valid_uids:
        logger.error(f"所有分组都无用户或不存在，跳过")
        return section_mount_targets

    # 非远程挂载授权
    if section_cfg.type != '远程挂载':
        for group in valid_groups:
            grant_group_rw_acl(src_path, group, recursive=True)

    # 对每个UID挂载目标
    for uid in valid_uids:
        user_path = Path('/vol1') / str(uid)
        if not user_path.exists():
            continue

        dst_path = user_path / section_cfg.dst
        empty_ok = ensure_dir_and_check_empty(dst_path)

        if not empty_ok:
            if section_cfg.conflict == '跳过':
                logger.warning(f"{dst_path} 非空且冲突策略设为跳过，忽略")
                continue
            elif section_cfg.conflict == '覆盖':
                logger.info(f"{dst_path} 非空且冲突策略为覆盖，将覆盖继续挂载")
            elif section_cfg.conflict == '重命名':
                new_dst = dst_path.with_name(f"my_{dst_path.name}")
                logger.warning(f"{dst_path} 非空，重命名为 {new_dst}")
                dst_path.rename(new_dst)
                dst_path.mkdir(parents=True, exist_ok=True)
        target = (str(src_path), str(dst_path))
        section_mount_targets.add(target)

    return section_mount_targets


def mount(config_targets) -> Set[Tuple[str, str]]:
    current_targets = set()
    skipped_targets = set()  # 记录跳过的挂载

    for src_path, dst_path in config_targets:
        try:
            # 检查是否需要挂载
            should_mount = handle_existing_mount(src_path, dst_path)

            if not should_mount:
                # 虽然跳过挂载，但仍然记录为当前有效的挂载
                current_targets.add((src_path, dst_path))
                skipped_targets.add((src_path, dst_path))
                continue

            # 执行挂载
            subprocess.run(['mount', '--bind', str(src_path), str(dst_path)], check=True)
            current_targets.add((src_path, dst_path))
            logger.info(f"挂载 {src_path} -> {dst_path} 完成")

        except Exception as e:
            logger.error(f"挂载失败: {e}")

    # 记录统计信息
    if skipped_targets:
        logger.info(f"跳过了 {len(skipped_targets)} 个已存在的相同挂载")

    return current_targets

################################################
# 主函数

def main():

    logger.info("读取配置文件中...")
    config = configparser.ConfigParser()
    config.read(CFG_FILE, encoding='utf-8')
    logger.info("配置文件读取完成")

    config_targets = set()
    logger.info("开始解析配置文件...")
    for section_cfg in next_config(config):
        section_mount_targets = list_section_mount_targets(section_cfg)
        for src_path, dst_path in section_mount_targets:
            config_targets.add((src_path, dst_path))
    logger.info("配置文件解析完成")

    logger.info("开始检查并卸载过期挂载...")
    unmount_obsolete_mounts(config_targets)
    logger.info("过期挂载检查完成")

    logger.info("开始挂载新配置...")
    current_targets: Set[Tuple[str, str]] = mount(config_targets)
    save_mounted_records(current_targets)
    logger.info("新配置挂载完成")

##################################################
# 监听目录

_config_last_modified: Optional[float] = None
_config_pending = False

class Vol1EventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            logger.info(f"检测到新目录: {event.src_path}，重新检查挂载")
            main()

class ConfigFileEventHandler(FileSystemEventHandler):
    @staticmethod
    def _maybe_handle(src_path):
        if src_path == str(CFG_FILE):
            global _config_last_modified, _config_pending
            _config_last_modified = time.time()
            _config_pending = True
            logger.info(f"检测到配置文件 {src_path} 被修改，15秒后自动重新挂载。")

    def on_modified(self, event):
        self._maybe_handle(event.src_path)
    def on_created(self, event):
        self._maybe_handle(event.src_path)
    def on_moved(self, event):
        self._maybe_handle(event.dest_path)  # 注意 FileMovedEvent 有 dest_path

def watch_vol1_and_cfg_blocking():
    observer = Observer()
    observer.schedule(Vol1EventHandler(), str(Path('/vol1')), recursive=False)
    observer.schedule(ConfigFileEventHandler(), str(CFG_FILE.parent), recursive=False)
    observer.start()

    global _config_last_modified, _config_pending
    try:
        while True:
            time.sleep(1)
            if _config_pending and _config_last_modified is not None:
                dt = time.time() - _config_last_modified
                if dt > 15:
                    logger.info("配置文件变更15秒后，自动重新挂载")
                    main()
                    _config_pending = False   # 重置，直到下次有新的变更
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == '__main__':
    # 开机启动时先等待10秒
    logger.info("初次启动，等待10秒后运行")
    time.sleep(10)
    # 立刻运行一次
    logger.info("正在运行...")
    main()
    # 监听 /vol1 目录变更
    logger.info("开始监听 /vol1 目录和 config.ini 变更...")
    watch_vol1_and_cfg_blocking()
