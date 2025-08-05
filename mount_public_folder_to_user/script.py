import configparser
import json
import logging
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
        logging.FileHandler(LOG_FILE, encoding='utf-8', mode='a'),
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
        try:
            subprocess.run(['umount', dst], check=True)
            logger.info(f"卸载过期挂载：{dst}")
            if not remove_dir_if_empty(Path(dst)):
                raise
        except Exception as e:
            logger.error(f"卸载 {dst} 失败，使用 Lazy 模式重试中：{e}")
            try:
                subprocess.run(['umount', '-l', dst], check=True)
                logger.info(f"Lazy 模式卸载 {dst} 成功，开始检测是否可删除目录")
                for i in range(5):
                    if remove_dir_if_empty(Path(dst)):
                        break
                    else:
                        logger.warning(f"目录 {dst} 尝试 {i+1} 次仍未变为空，未删除。")
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
    for src_path, dst_path in config_targets:
        try:
            subprocess.run(['mount', '--bind', str(src_path), str(dst_path)], check=True)
            current_targets.add((src_path, dst_path))
            logger.info(f"挂载 {src_path} -> {dst_path} 完成")
        except Exception as e:
            logger.error(f"挂载失败: {e}")
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
