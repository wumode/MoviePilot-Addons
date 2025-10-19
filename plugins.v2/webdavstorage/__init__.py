from pathlib import Path
from typing import Any, List, Dict, Tuple, Optional
from datetime import datetime

from app import schemas
from app.core.event import eventmanager, Event
from app.log import logger
from app.plugins import _PluginBase
from app.schemas.types import ChainEventType
from app.helper.storage import StorageHelper
from app.schemas import StorageOperSelectionEventData, FileItem

from .webdavapi import WebdavAPI

class WebdavStorage(_PluginBase):
    # 插件名称
    plugin_name = "WebDAV存储"
    # 插件描述
    plugin_desc = "使存储支持WebDAV。"
    # 插件图标
    plugin_icon = "https://raw.githubusercontent.com/wumode/MoviePilot-Addons/refs/heads/main/icons/disk.png"
    # 插件版本
    plugin_version = "1.0.2"
    # 插件作者
    plugin_author = "wumode"
    # 作者主页
    author_url = "https://github.com/wumode"
    # 插件配置项ID前缀
    plugin_config_prefix = "webdavstorage_"
    # 加载顺序
    plugin_order = 99
    # 可使用的用户级别
    auth_level = 2

    _enabled = False
    _client: Optional[WebdavAPI] = None
    _disk_name = 'WebDAV'
    _server: str = ''
    _username: str = ''
    _password: str = ''
    _root: str = '/'

    def init_plugin(self, config: dict = None):
        """
        初始化插件
        """
        if config:
            self._enabled = config.get("enabled")
            self._server = config.get("server")
            self._username = config.get("username")
            self._password = config.get("password")
            self._root = config.get("root") or '/'

        if self._enabled:
            self._client = WebdavAPI(
                conf={
                    "webdav_url": self._server,
                    "username": self._username,
                    "password": self._password,
                    "disable_check": True,
                    "root": self._root,
                    "name": self._disk_name # Pass the storage name to WebdavAPI
                }
            )
            storage_helper = StorageHelper()
            storages = storage_helper.get_storagies()
            if not any(
                    s.type == self._disk_name and s.name == self._disk_name
                    for s in storages
            ):
                # 添加云盘存储配置
                storage_helper.add_storage(
                    storage=self._disk_name, name=self._disk_name, conf={}
                )

    def get_state(self) -> bool:
        return self._enabled

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        pass

    def get_api(self) -> List[Dict[str, Any]]:
        pass

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """
        拼装插件配置页面，需要返回两块数据：1、页面配置；2、数据结构
        """
        return [
            {
                "component": "VForm",
                "content": [
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [
                                    {
                                        "component": "VSwitch",
                                        "props": {
                                            "model": "enabled",
                                            "label": "启用插件",
                                        },
                                    }
                                ],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [
                                    {
                                        "component": "VTextField",
                                        "props": {
                                            "model": "server",
                                            "label": "服务器",
                                            "placeholder": "https://domain:port/"
                                        },
                                    }
                                ],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [
                                    {
                                        "component": "VTextField",
                                        "props": {
                                            "model": "username",
                                            "label": "用户名",
                                        },
                                    }
                                ],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [
                                    {
                                        "component": "VTextField",
                                        "props": {
                                            "model": "password",
                                            "label": "密码",
                                        },
                                    }
                                ],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [
                                    {
                                        "component": "VTextField",
                                        "props": {
                                            "model": "root",
                                            "label": "根目录",
                                            "placeholder": "/"
                                        },
                                    }
                                ],
                            },
                        ],
                    },
                ],
            }
        ], {
            "enabled": False,
            "server": "",
            "username": "",
            "password": "",
            "root": "",
        }

    def get_page(self) -> List[dict]:
        pass

    def get_module(self) -> Dict[str, Any]:
        """
        获取插件模块声明，用于胁持系统模块实现（方法名：方法实现）
        {
            "id1": self.xxx1,
            "id2": self.xxx2,
        }
        """
        return {
            "list_files": self.list_files,
            "any_files": self.any_files,
            "download_file": self.download_file,
            "upload_file": self.upload_file,
            "delete_file": self.delete_file,
            "rename_file": self.rename_file,
            "get_file_item": self.get_file_item,
            "get_parent_item": self.get_parent_item,
            "snapshot_storage": self.snapshot_storage,
            "storage_usage": self.storage_usage,
            "support_transtype": self.support_transtype,
            "create_folder": self.create_folder,
            "exists": self.exists,
            "get_item": self.get_item,
        }

    @eventmanager.register(ChainEventType.StorageOperSelection)
    def storage_oper_selection(self, event: Event):
        """
        监听存储选择事件，返回当前类为操作对象
        """
        if not self._enabled:
            return
        event_data: StorageOperSelectionEventData = event.event_data
        if event_data.storage == self._disk_name:
            event_data.storage_oper = self._client

    def list_files(self, fileitem: schemas.FileItem, recursion: bool = False) -> Optional[List[schemas.FileItem]]:
        """
        查询当前目录下所有目录和文件
        """
        if fileitem.storage != self._disk_name:
            return None

        def __get_files(_item: FileItem, _r: Optional[bool] = False):
            """
            递归处理
            """
            _items = self._client.list(_item)
            if _items:
                if _r:
                    for t in _items:
                        if t.type == "dir":
                            __get_files(t, _r)
                        else:
                            result.append(t)
                else:
                    result.extend(_items)

        # 返回结果
        result = []
        __get_files(fileitem, recursion)

        return result

    def any_files(self, fileitem: schemas.FileItem, extensions: list = None) -> Optional[bool]:
        """
        查询当前目录下是否存在指定扩展名任意文件
        """
        if fileitem.storage != self._disk_name:
            return None
        
        def __any_file(_item: FileItem):
            """
            递归处理
            """
            _items = self._client.list(_item)
            if _items:
                if not extensions:
                    return True
                for t in _items:
                    if (t.type == "file"
                            and t.extension
                            and f".{t.extension.lower()}" in extensions):
                        return True
                    elif t.type == "dir":
                        if __any_file(t):
                            return True
            return False

        # 返回结果
        return __any_file(fileitem)

    def create_folder(self, fileitem: schemas.FileItem, name: str) -> Optional[schemas.FileItem]:
        """
        创建目录
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.create_folder(fileitem, name)

    def download_file(self, fileitem: schemas.FileItem, path: Path = None) -> Optional[Path]:
        """
        下载文件
        :param fileitem: 文件项
        :param path: 本地保存路径
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.download(fileitem, path)

    def upload_file(
        self, fileitem: schemas.FileItem, path: Path, new_name: Optional[str] = None
    ) -> Optional[schemas.FileItem]:
        """
        上传文件
        :param fileitem: 保存目录项
        :param path: 本地文件路径
        :param new_name: 新文件名
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.upload(fileitem, path, new_name)

    def delete_file(self, fileitem: schemas.FileItem) -> Optional[bool]:
        """
        删除文件或目录
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.delete(fileitem)

    def rename_file(self, fileitem: schemas.FileItem, name: str) -> Optional[bool]:
        """
        重命名文件或目录
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.rename(fileitem, name)

    def exists(self, fileitem: schemas.FileItem) -> Optional[bool]:
        """
        判断文件或目录是否存在
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.get_item(Path(fileitem.path)) is not None

    def get_item(self, fileitem: schemas.FileItem) -> Optional[schemas.FileItem]:
        """
        查询目录或文件
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.get_item(Path(fileitem.path))

    def get_file_item(self, storage: str, path: Path) -> Optional[schemas.FileItem]:
        """
        根据路径获取文件项
        """
        if storage != self._disk_name:
            return None
        return self._client.get_item(path)

    def get_parent_item(self, fileitem: schemas.FileItem) -> Optional[schemas.FileItem]:
        """
        获取上级目录项
        """
        if fileitem.storage != self._disk_name:
            return None
        return self._client.get_parent(fileitem)

    def snapshot_storage(
        self,
        storage: str,
        path: Path,
        last_snapshot_time: float = None,
        max_depth: int = 5,
    ) -> Optional[Dict[str, Dict]]:
        """
        快照存储
        :param storage: 存储类型
        :param path: 路径
        :param last_snapshot_time: 上次快照时间，用于增量快照
        :param max_depth: 最大递归深度，避免过深遍历
        """
        if storage != self._disk_name:
            return None
        
        files_info = {}

        def __snapshot_file(_fileitm: schemas.FileItem, current_depth: int):
            """
            递归获取文件信息
            """
            if current_depth > max_depth:
                return

            if _fileitm.type == "dir":
                for sub_file in self._client.list(_fileitm):
                    __snapshot_file(sub_file, current_depth + 1)
            else:
                files_info[_fileitm.path] = {
                    "size": _fileitm.size or 0,
                    "modify_time": getattr(_fileitm, "modify_time", 0),
                    "type": _fileitm.type,
                }

        fileitem = self._client.get_item(path)
        if not fileitem:
            return {}

        __snapshot_file(fileitem, 0)

        return files_info

    def storage_usage(self, storage: str) -> Optional[schemas.StorageUsage]:
        """
        存储使用情况
        """
        if storage != self._disk_name:
            return None
        return self._client.usage()

    def support_transtype(self, storage: str) -> Optional[dict]:
        """
        获取支持的整理方式
        """
        if storage != self._disk_name:
            return None

        return {"move": "移动", "copy": "复制"}

    def stop_service(self):
        """
        退出插件
        """
        pass
