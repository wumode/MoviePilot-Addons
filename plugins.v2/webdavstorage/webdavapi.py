from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime

from webdav3.client import Client

from app import schemas
from app.core.config import settings, global_vars
from app.log import logger
from app.modules.filemanager.storages import transfer_process

class WebdavAPI:
    """
    Webdav 基本操作
    """

    def __init__(self, conf: Dict):
        self.conf = conf
        self._root = conf.get('root', '/')
        if not self._root.startswith('/'):
            self._root = '/' + self._root
        if not self._root.endswith('/'):
            self._root = self._root + '/'
        self.client = Client(
            {
                'webdav_hostname': conf.get('webdav_url'),
                'webdav_login': conf.get('username'),
                'webdav_password': conf.get('password'),
                'webdav_disable_check': conf.get('disable_check', False),
                'webdav_root': conf.get('root')
            }
        )

    def _full_path(self, path: str) -> str:
        """Converts a path relative to the configured root to a full WebDAV path."""
        if path.startswith('/'):
            path = path[1:]
        return self._root + path

    def _relative_path(self, full_path: str) -> str:
        """Converts a full WebDAV path to a path relative to the configured root."""
        if full_path.startswith(self._root):
            return '/' + full_path[len(self._root):]
        return full_path

    def list(self, fileitem: schemas.FileItem) -> List[schemas.FileItem]:
        """
        浏览文件
        """
        try:
            items = self.client.list(remote_path=fileitem.path, get_info=True)
            result = []
            for item in items:
                full_item_path = item.get('path')
                
                is_dir = item.get('isdir', False)
                name = Path(full_item_path).name
                
                # Extract extension for files
                extension = None
                if not is_dir:
                    extension = Path(name).suffix.lstrip('.')
                
                # Convert modified time to datetime object
                modified_str = item.get('modified')
                modified = None
                if modified_str:
                    try:
                        # Example format: 'Wed, 03 Sep 2025 10:00:00 GMT'
                        modified = datetime.strptime(modified_str, '%a, %d %b %Y %H:%M:%S %Z')
                    except ValueError:
                        pass # Handle other possible date formats if necessary

                result.append(
                    schemas.FileItem(
                        path=self._relative_path(full_item_path),
                        name=name,
                        type="dir" if is_dir else "file",
                        size=item.get('size', 0),
                        modified=modified,
                        extension=extension,
                        storage=fileitem.storage
                    )
                )
            return result
        except Exception as e:
            logger.error(f"Error listing WebDAV directory {fileitem.path!r}: {e}")
            return []

    def create_folder(self, fileitem: schemas.FileItem, name: str) -> Optional[schemas.FileItem]:
        """
        创建目录
        :param fileitem: 父目录
        :param name: 目录名
        """
        try:
            new_folder_relative_path = Path(fileitem.path) / name
            self.client.mkdir(remote_path=str(new_folder_relative_path))
            return schemas.FileItem(
                path=str(new_folder_relative_path),
                name=name,
                type="dir",
                size=0,
                storage=fileitem.storage
            )
        except Exception as e:
            logger.error(f"Error creating folder {name} in {fileitem.path}: {e}")
            return None

    def get_folder(self, path: Path) -> Optional[schemas.FileItem]:
        """
        获取目录，如目录不存在则创建
        """
        try:
            if not self.client.check(remote_path=str(path)):
                self.client.mkdir(remote_path=str(path))
            
            # After ensuring it exists, get its details
            item_info = self.client.info(remote_path=str(path))
            if item_info:
                name = item_info.get('name')
                modified_str = item_info.get('modified')
                modified = None
                if modified_str:
                    try:
                        modified = datetime.strptime(modified_str, '%a, %d %b %Y %H:%M:%S %Z')
                    except ValueError:
                        pass
                return schemas.FileItem(
                    path=f"{path}",
                    name=name,
                    type="dir",
                    size=item_info.get('size', 0),
                    modified=modified,
                    storage=self.conf.get('name', 'webdav') # Assuming storage name is in conf
                )
            return None
        except Exception as e:
            logger.error(f"Error getting or creating folder {path}: {e}")
            return None

    def get_item(self, path: Path) -> Optional[schemas.FileItem]:
        """
        获取文件或目录，不存在返回None
        """
        try:
            item_info = self.client.info(remote_path=str(path))
            if item_info:
                is_dir = item_info.get('isdir', False)
                name = item_info.get('name')
                extension = None
                if not is_dir:
                    extension = Path(name).suffix.lstrip('.')
                
                modified_str = item_info.get('modified')
                modified = None
                if modified_str:
                    try:
                        modified = datetime.strptime(modified_str, '%a, %d %b %Y %H:%M:%S %Z')
                    except ValueError:
                        pass

                return schemas.FileItem(
                    path=str(path),
                    name=name,
                    type="dir" if is_dir else "file",
                    size=item_info.get('size', 0),
                    modified=modified,
                    extension=extension,
                    storage=self.conf.get('name', 'webdav')
                )
            return None
        except Exception as e:
            logger.error(f"Error getting item {path}: {e}")
            return None

    def get_parent(self, fileitem: schemas.FileItem) -> Optional[schemas.FileItem]:
        """
        获取父目录
        """
        # Get the parent path relative to the root
        parent_path = Path(fileitem.path).parent
        return self.get_item(parent_path)

    def delete(self, fileitem: schemas.FileItem) -> bool:
        """
        删除文件
        """
        try:
            self.client.clean(remote_path=fileitem.path)
            return True
        except Exception as e:
            logger.error(f"Error deleting {fileitem.path}: {e}")
            return False

    def rename(self, fileitem: schemas.FileItem, name: str) -> bool:
        """
        重命名文件
        """
        try:
            old_relative_path = Path(fileitem.path)
            new_relative_path = old_relative_path.parent / name
            
            self.client.move(remote_path_from=str(old_relative_path), remote_path_to=str(new_relative_path))
            return True
        except Exception as e:
            logger.error(f"Error renaming {fileitem.path} to {name}: {e}")
            return False

    def download(self, fileitem: schemas.FileItem, path: Path = None) -> Optional[Path]:
        """
        下载文件，保存到本地，返回本地临时文件地址
        :param fileitem: 文件项
        :param path: 文件保存路径
        """
        try:
            local_path = path if path else settings.TEMP_PATH / fileitem.name
            self.client.download(remote_path=fileitem.path, local_path=str(local_path))
            return local_path
        except Exception as e:
            logger.error(f"Error downloading {fileitem.path}: {e}")
            return None

    def upload(self, fileitem: schemas.FileItem,
               path: Path, new_name: Optional[str] = None) -> Optional[schemas.FileItem]:
        """
        上传文件
        :param fileitem: 上传目录项
        :param path: 本地文件路径
        :param new_name: 上传后文件名
        """
        progress_callback = transfer_process(path.as_posix())

        def update_progress(current, total) -> None:
            progress_callback(100*current/total)

        try:
            remote_relative_path = Path(fileitem.path) / (new_name if new_name else path.name)
            self.client.upload_file(remote_path=str(remote_relative_path), local_path=str(path), progress=update_progress)
            return self.get_item(remote_relative_path)
        except Exception as e:
            logger.error(f"Error uploading {path} to {fileitem.path}: {e}")
            return None

    def detail(self, fileitem: schemas.FileItem) -> Optional[schemas.FileItem]:
        """
        获取文件详情
        """
        return self.get_item(Path(fileitem.path))

    def copy(self, fileitem: schemas.FileItem, path: Path, new_name: str) -> bool:
        """
        复制文件
        :param fileitem: 文件项
        :param path: 目标目录
        :param new_name: 新文件名
        """
        destination_relative_path = path / new_name
        try:
            self.client.copy(remote_path_from=fileitem.path, remote_path_to=str(destination_relative_path))
            return True
        except Exception as e:
            logger.error(f"Error copying {fileitem.path} to {destination_relative_path}: {e}")
            return False

    def move(self, fileitem: schemas.FileItem, path: Path, new_name: str) -> bool:
        """
        移动文件
        :param fileitem: 文件项
        :param path: 目标目录
        :param new_name: 新文件名
        """
        destination_relative_path = path / new_name
        try:
            self.client.move(remote_path_from=fileitem.path, remote_path_to=str(destination_relative_path))
            return True
        except Exception as e:
            logger.error(f"Error moving {fileitem.path} to {destination_relative_path}: {e}")
            return False

    def link(self, fileitem: schemas.FileItem, target_file: Path) -> bool:
        """
        硬链接文件
        """
        pass

    def softlink(self, fileitem: schemas.FileItem, target_file: Path) -> bool:
        """
        软链接文件
        """
        pass

    def usage(self) -> Optional[schemas.StorageUsage]:
        """
        存储使用情况
        """
        pass