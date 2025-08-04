import csv
import os
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

import pytz
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from requests import Response

from app import schemas
from app.core.config import settings
from app.core.event import eventmanager, Event
from app.log import logger
from app.plugins import _PluginBase
from app.schemas.types import EventType, NotificationType
from app.utils.http import RequestUtils
from app.utils.ip import IpUtils
from app.utils.system import SystemUtils


class CloudflareSpeedTestForClash(_PluginBase):
    # 插件名称
    plugin_name = "Best Cloudflare IP"
    # 插件描述
    plugin_desc = "将优选 Cloudflare IP 同步到 Clash Rule Provider。"
    # 插件图标
    plugin_icon = "cloudflare.jpg"
    # 插件版本
    plugin_version = "1.0"
    # 插件作者
    plugin_author = "thsrite,wumode"
    # 作者主页
    author_url = "https://github.com/wumode"
    # 插件配置项ID前缀
    plugin_config_prefix = "cloudflarespeedtestforclash_"
    # 加载顺序
    plugin_order = 12
    # 可使用的用户级别
    auth_level = 1

    # 私有属性
    _enabled = False
    _cf_ip: List[str] = None
    _scheduler = None
    _cron = None
    _onlyonce = False
    _ipv4 = False
    _ipv6 = False
    _version = None
    _additional_args: str = None
    _notify = False
    _check = False
    _cf_path = None
    _cf_ipv4 = None
    _cf_ipv6 = None
    _result_file = None
    _release_prefix = 'https://github.com/XIU2/CloudflareSpeedTest/releases/download'
    _binary_name = 'cfst'
    _ips_number = 3
    _add_to_crp = False

    def init_plugin(self, config: dict = None):
        # 停止现有任务
        self.stop_service()

        # 读取配置
        if config:
            self._enabled = config.get("enabled")
            self._onlyonce = config.get("onlyonce")
            self._cron = config.get("cron")
            self._cf_ip = config.get("cf_ip") or []
            self._cf_ip = [ip.strip() for ip in self._cf_ip]
            self._cf_ip = [ip for ip in self._cf_ip if IpUtils.is_ipv4(ip) or IpUtils.is_ipv6(ip)]
            self._version = config.get("version")
            self._ipv4 = config.get("ipv4")
            self._ipv6 = config.get("ipv6")
            self._additional_args = config.get("additional_args")
            self._notify = config.get("notify")
            self._ips_number = config.get("ips_number") or 3
            self._add_to_crp = config.get("add_to_crp")

        if (self._ipv4 or self._ipv6) and self._onlyonce:
            try:
                self._scheduler = BackgroundScheduler(timezone=settings.TZ)
                logger.info(f"Cloudflare CDN优选服务启动，立即运行一次")
                self._scheduler.add_job(func=self.cloudflare_speed_test, trigger='date',
                                        run_date=datetime.now(tz=pytz.timezone(settings.TZ)) + timedelta(seconds=3),
                                        name="Cloudflare优选")
                # 关闭一次性开关
                self._onlyonce = False
                self.__update_config()
                # 启动任务
                if self._scheduler.get_jobs():
                    self._scheduler.print_jobs()
                    self._scheduler.start()
            except Exception as err:
                logger.error(f"Cloudflare CDN优选服务出错：{str(err)}")
                self.systemmessage.put(f"Cloudflare CDN优选服务出错：{str(err)}", title="Cloudflare IP优选")
                return

    def extract_ip_addresses(self, csv_file_path, number)->Optional[List[str]]:
        """
        reads a CSV file, extracts the IP addresses from the first 10 rows,
        and returns them as a list.

        Args:
            csv_file_path (str): The path to the CSV file.
            number (int): The number of IP addresses to return.

        Returns:
            list: A list of IP addresses.
        """
        ip_addresses = []
        try:
            with open(csv_file_path, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                # Skip the header row
                next(reader)

                # Read up to the first 10 rows
                for i, row in enumerate(reader):
                    if i >= number:
                        break
                    # Ensure the row has at least one column before trying to access it
                    if row:
                        ip_addresses.append(row[0])

        except FileNotFoundError:
            logger.error(f"Error: The file '{csv_file_path}' was not found.")
            return None
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return None

        return ip_addresses

    @eventmanager.register(EventType.PluginAction)
    def cloudflare_speed_test(self, event: Event = None):
        """
        CloudflareSpeedTest优选
        """
        if event:
            event_data = event.event_data
            if not event_data or event_data.get("action") != "cloudflare_ip":
                return

        self._cf_path = self.get_data_path()
        self._cf_ipv4 = os.path.join(self._cf_path, "ip.txt")
        self._cf_ipv6 = os.path.join(self._cf_path, "ipv6.txt")
        result_v4_path = os.path.join(self._cf_path, "result_v4.csv")
        result_v6_path = os.path.join(self._cf_path, "result_v6.csv")

        if event and event.event_data:
            logger.info("收到命令，开始 Cloudflare IP 优选 ...")
            self.post_message(channel=event.event_data.get("channel"),
                              title="开始 Cloudflare IP优选 ...",
                              userid=event.event_data.get("user"))

        # ipv4和ipv6必须其一
        if not self._ipv4 and not self._ipv6:
            self._ipv4 = True
            self.__update_config()
            logger.warn(f"Cloudflare CDN优选未指定ip类型，默认ipv4")

        err_flag, release_version = self.__check_environment()
        if err_flag and release_version:
            # 更新版本
            self._version = release_version
            self.__update_config()
        if not err_flag:
            logger.error('环境检查失败')
            return
        logger.info("正在进行CLoudflare CDN优选，请耐心等待")
        cfst_path = os.path.join(self._cf_path, self._binary_name)

        if SystemUtils.is_windows():
            ipv4_command = [cfst_path, self._additional_args, '-o', result_v4_path, '-f', self._cf_ipv4]
            ipv6_command = [cfst_path, self._additional_args, '-o', result_v6_path, '-f', self._cf_ipv6]
        else:
            ipv4_command = [cfst_path] + self._additional_args.split(' ') + ['-o', result_v4_path, '-f', self._cf_ipv4]
            ipv6_command = [cfst_path] + self._additional_args.split(' ') + ['-o', result_v6_path, '-f', self._cf_ipv6]
        best_ipv4 = []
        best_ipv6 = []
        if self._ipv4:
            logger.info(f'正在执行优选命令 {' '.join(ipv4_command)}')
            res, message = SystemUtils.execute_with_subprocess(ipv4_command)
            if not res:
                logger.error(f"Error: {message}")
                self.post_message(
                    mtype=NotificationType.SiteMessage,
                    title="【Cloudflare优选任务失败】",
                    text=f"Error: {message}",
                )
                return
            best_ipv4 = self.extract_ip_addresses(result_v4_path, self._ips_number) or []
        if self._ipv6:
            logger.info(f'正在执行优选命令 {' '.join(ipv6_command)}')
            res, message = SystemUtils.execute_with_subprocess(ipv6_command)
            if not res:
                logger.error(f"Error: {message}")
                self.post_message(
                    mtype=NotificationType.SiteMessage,
                    title="【Cloudflare优选任务失败】",
                    text=f"Error: {message}",
                )
                return
            best_ipv6 = self.extract_ip_addresses(result_v6_path, self._ips_number) or []
        best_ips = best_ipv4 + best_ipv6 + self._cf_ip
        logger.info(f"获取到最优ip==>{best_ips}")

        crp_config = self.get_config("ClashRuleProvider")
        if self._add_to_crp and crp_config.get("enabled"):
            logger.info("通知 Clash Rule Provider 更新 IP ...")
            self.eventmanager.send_event(
                EventType.PluginAction,
                {
                    "action": "update_cloudflare_ips",
                    "ips": best_ips
                })

        if self._notify:
            self.post_message(
                mtype=NotificationType.SiteMessage,
                title="【Cloudflare优选任务完成】",
                text=f"优选 IP：\n{'\n'.join(best_ips)}",
            )


    def __check_cf_ip(self, hosts):
        """
        校正cf优选ip
        防止特殊情况下cf优选ip和自定义hosts插件中ip不一致
        """
        # 统计每个IP地址出现的次数
        ip_count = {}
        for host in hosts:
            if host:
                ip = host.split()[0]
                if ip in ip_count:
                    ip_count[ip] += 1
                else:
                    ip_count[ip] = 1

        # 找出出现次数最多的IP地址
        max_ips = []  # 保存最多出现的IP地址
        max_count = 0
        for ip, count in ip_count.items():
            if count > max_count:
                max_ips = [ip]  # 更新最多的IP地址
                max_count = count
            elif count == max_count:
                max_ips.append(ip)

        # 如果出现次数最多的ip不止一个，则不做兼容处理
        if len(max_ips) != 1:
            return

        if max_ips[0] != self._cf_ip:
            self._cf_ip = max_ips[0]
            logger.info(f"获取到自定义hosts插件中ip {max_ips[0]} 出现次数最多，已自动校正优选ip")

    def __check_environment(self):
        """
        环境检查
        """
        # 是否安装标识
        install_flag = False

        # 判断目录是否存在
        cfst_path = Path(self._cf_path) / self._binary_name

        # 获取CloudflareSpeedTest最新版本
        release_version = self.__get_release_version()
        if not release_version:
            # 如果升级失败但是有可执行文件CloudflareST，则可继续运行，反之停止
            if cfst_path.exists():
                logger.warn(f"获取CloudflareSpeedTest版本失败，存在可执行版本，继续运行")
                return True, None
            elif self._version:
                logger.error(f"获取CloudflareSpeedTest版本失败，获取上次运行版本{self._version}，开始安装")
                install_flag = True
            else:
                release_version = "v2.2.2"
                self._version = release_version
                logger.error(f"获取CloudflareSpeedTest版本失败，获取默认版本{release_version}，开始安装")
                install_flag = True

        # 有更新
        if not install_flag and release_version != self._version:
            logger.info(f"检测到CloudflareSpeedTest有版本[{release_version}]更新，开始安装")
            install_flag = True

        # 重装后数据库有版本数据，但是本地没有则重装
        if not install_flag \
                and release_version == self._version \
                and not cfst_path.exists() \
                and not Path(f'{self._cf_path}/cfst.exe').exists():
            logger.warn(f"未检测到CloudflareSpeedTest本地版本，重新安装")
            install_flag = True

        if not install_flag:
            logger.info(f"CloudflareSpeedTest无新版本，存在可执行版本，继续运行")
            return True, None

        # 检查环境、安装
        if SystemUtils.is_windows():
            # windows
            cf_file_name = 'cfst_windows_amd64.zip'
            download_url = f'{self._release_prefix}/{release_version}/{cf_file_name}'
            return self.__os_install(download_url, cf_file_name, release_version,
                                     f"ditto -V -x -k --sequesterRsrc {self._cf_path}/{cf_file_name} {self._cf_path}")
        elif SystemUtils.is_macos():
            # mac
            uname = SystemUtils.execute('uname -m')
            arch = 'amd64' if uname == 'x86_64' else 'arm64'
            cf_file_name = f'cfst_darwin_{arch}.zip'
            download_url = f'{self._release_prefix}/{release_version}/{cf_file_name}'
            return self.__os_install(download_url, cf_file_name, release_version,
                                     f"ditto -V -x -k --sequesterRsrc {self._cf_path}/{cf_file_name} {self._cf_path}")
        else:
            # docker
            uname = SystemUtils.execute('uname -m')
            arch = 'amd64' if uname == 'x86_64' else 'arm64'
            cf_file_name = f'cfst_linux_{arch}.tar.gz'
            download_url = f'{self._release_prefix}/{release_version}/{cf_file_name}'
            return self.__os_install(download_url, cf_file_name, release_version,
                                     f"tar -zxf {self._cf_path}/{cf_file_name} -C {self._cf_path}")

    def __os_install(self, download_url, cf_file_name, release_version, unzip_command):
        """
        macos docker安装cloudflare
        """
        # 手动下载安装包后，无需在此下载
        if not Path(f'{self._cf_path}/{cf_file_name}').exists():
            # 首次下载或下载新版压缩包
            proxies = settings.PROXY
            response = RequestUtils().get_res(download_url, proxies=proxies, stream=True)
            if response and response.status_code == 200:
                with open(Path(f'{self._cf_path}/{cf_file_name}'), 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)

        # 判断是否下载好安装包
        if Path(f'{self._cf_path}/{cf_file_name}').exists():
            try:
                if SystemUtils.is_windows():
                    with zipfile.ZipFile(f'{self._cf_path}/{cf_file_name}', 'r') as zip_ref:
                        # 解压ZIP文件中的所有文件到指定目录
                        zip_ref.extractall(self._cf_path)
                    if Path(f'{self._cf_path}\\CloudflareST.exe').exists():
                        logger.info(f"CloudflareSpeedTest安装成功，当前版本：{release_version}")
                        return True, release_version
                    else:
                        logger.error(f"CloudflareSpeedTest安装失败，请检查")
                        os.system(f'rd /s /q \"{self._cf_path}\"')
                        return False, None
                # 解压
                os.system(f'{unzip_command}')
                # 删除压缩包
                os.system(f'rm -rf {self._cf_path}/{cf_file_name}')
                if Path(f'{self._cf_path}/{self._binary_name}').exists():
                    logger.info(f"CloudflareSpeedTest安装成功，当前版本：{release_version}")
                    return True, release_version
                else:
                    logger.error(f"CloudflareSpeedTest安装失败，请检查")
                    os.removedirs(self._cf_path)
                    return False, None
            except Exception as err:
                # 如果升级失败但是有可执行文件CloudflareST，则可继续运行，反之停止
                if Path(f'{self._cf_path}/{self._binary_name}').exists() or \
                        Path(f'{self._cf_path}\\CloudflareST.exe').exists():
                    logger.error(f"CloudflareSpeedTest安装失败：{str(err)}，继续使用现版本运行")
                    return True, None
                else:
                    logger.error(f"CloudflareSpeedTest安装失败：{str(err)}，无可用版本，停止运行")
                    if SystemUtils.is_windows():
                        os.system(f'rd /s /q \"{self._cf_path}\"')
                    else:
                        os.removedirs(self._cf_path)
                    return False, None
        else:
            # 如果升级失败但是有可执行文件CloudflareST，则可继续运行，反之停止
            if Path(f'{self._cf_path}/{self._binary_name}').exists() or \
                    Path(f'{self._cf_path}\\CloudflareST.exe').exists():
                logger.warn(f"CloudflareSpeedTest安装失败，存在可执行版本，继续运行")
                return True, None
            else:
                logger.error(f"CloudflareSpeedTest安装失败，无可用版本，停止运行")
                if SystemUtils.is_windows():
                    os.system(f'rd /s /q \"{self._cf_path}\"')
                else:
                    os.removedirs(self._cf_path)
                return False, None

    def __get_windows_cloudflarest(self, download_url, proxies):
        response = Response()
        try:
            response = requests.get(download_url, stream=True, proxies=proxies if proxies else None)
        except requests.exceptions.RequestException as e:
            logger.error(f"CloudflareSpeedTest下载失败：{str(e)}")
        if response.status_code == 200:
            with open(f'{self._cf_path}\\CloudflareST_windows_amd64.zip', 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)

    @staticmethod
    def __get_release_version():
        """
        获取CloudflareSpeedTest最新版本
        """
        version_res = RequestUtils().get_res(
            "https://api.github.com/repos/XIU2/CloudflareSpeedTest/releases/latest")
        if not version_res:
            version_res = RequestUtils(proxies=settings.PROXY).get_res(
                "https://api.github.com/repos/XIU2/CloudflareSpeedTest/releases/latest")
        if version_res:
            ver_json = version_res.json()
            version = f"{ver_json['tag_name']}"
            return version
        else:
            return None

    def __update_config(self):
        """
        更新优选插件配置
        """
        self.update_config({
            "enabled": self._enabled,
            "onlyonce": False,
            "cron": self._cron,
            "cf_ip": self._cf_ip,
            "version": self._version,
            "ipv4": self._ipv4,
            "ipv6": self._ipv6,
            "additional_args": self._additional_args,
            "notify": self._notify,
            'ips_number': self._ips_number,
            'add_to_crp': self._add_to_crp,
        })

    def get_state(self) -> bool:
        return self._enabled

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        """
        定义远程控制命令
        :return: 命令关键字、事件、描述、附带数据
        """
        return [{
            "cmd": "/cloudflare_ip",
            "event": EventType.PluginAction,
            "desc": "Cloudflare IP优选",
            "data": {
                "action": "cloudflare_ip"
            }
        }]

    def get_api(self) -> List[Dict[str, Any]]:
        return [{
            "path": "/cloudflare_speedtest",
            "endpoint": self.cloudflare_speedtest,
            "methods": ["GET"],
            "summary": "Cloudflare IP优选",
            "description": "Cloudflare IP优选",
        }]

    def get_service(self) -> List[Dict[str, Any]]:
        """
        注册插件公共服务
        [{
            "id": "服务ID",
            "name": "服务名称",
            "trigger": "触发器：cron/interval/date/CronTrigger.from_crontab()",
            "func": self.xxx,
            "kwargs": {} # 定时器参数
        }]
        """
        if self.get_state():
            return [
                {
                    "id": "CloudflareSpeedTest",
                    "name": "Cloudflare IP优选服务",
                    "trigger": CronTrigger.from_crontab(self._cron),
                    "func": self.cloudflare_speed_test,
                    "kwargs": {}
                }
            ]
        return []

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """
        拼装插件配置页面，需要返回两块数据：1、页面配置；2、数据结构
        """
        return [
            {
                'component': 'VForm',
                'content': [

                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'enabled',
                                            'label': '启用插件',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'ipv4',
                                            'label': 'IPv4',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'ipv6',
                                            'label': 'IPv6',
                                        }
                                    }
                                ]
                            },
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'onlyonce',
                                            'label': '立即运行一次',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'notify',
                                            'label': '运行时通知',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'add_to_crp',
                                            'label': '添加到 Clash Rule Provider',
                                            'hint': '将优选 IP 添加到 Clash Rule Provider'
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [

                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VCronField',
                                        'props': {
                                            'model': 'cron',
                                            'label': '优选周期',
                                            'placeholder': '0 4 * * *'
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'version',
                                            'readonly': True,
                                            'label': 'CloudflareSpeedTest版本',
                                            'placeholder': '暂未安装'
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 4,
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'ips_number',
                                            'label': '优选 IP 数量',
                                            'placeholder': '3',
                                            'type': 'number',
                                            'max': 99,
                                            'min': 1,
                                        }
                                    }
                                ]
                            },
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                },
                                'content': [
                                    {
                                        'component': 'VCombobox',
                                        'props': {
                                            'model': 'cf_ip',
                                            'label': '附加 Cloudflare IPs',
                                            'multiple': True,
                                            'chips': True,
                                            'closable-chips': True,
                                            'clearable': True,
                                            'hint': '用于补充测速结果'
                                        }
                                    }
                                ]
                            },
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'additional_args',
                                            'label': '高级参数',
                                            'placeholder': '-dd'
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                },
                                'content': [
                                    {
                                        'component': 'VAlert',
                                        'props': {
                                            'type': 'info',
                                            'variant': 'tonal',
                                            'text': 'F12看请求的Server属性，如果是cloudflare说明该站点支持Cloudflare IP优选。'
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ], {
            "cf_ip": [],
            "cron": "0 4 * * *",
            "version": "",
            "ips_number": 3,
            "ipv4": True,
            "ipv6": False,
            "onlyonce": False,
            "enabled": False,
            "notify": True,
            "additional_args": ""
        }

    def get_page(self) -> List[dict]:
        pass

    def cloudflare_speedtest(self, apikey: str) -> schemas.Response:
        """
        API调用CloudflareSpeedTest IP优选
        """
        if apikey != settings.API_TOKEN:
            return schemas.Response(success=False, message="API密钥错误")
        self.cloudflare_speed_test()
        return schemas.Response(success=True)

    def stop_service(self):
        """
        退出插件
        """
        if self._scheduler:
            try:
                self._scheduler.remove_all_jobs()
                if self._scheduler.running:
                    self._scheduler.shutdown()
                self._scheduler = None
            except Exception as e:
                logger.error(f"退出插件失败：{e}")