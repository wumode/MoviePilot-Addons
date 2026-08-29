import asyncio
from typing import Optional, Type

from pydantic import BaseModel

from app.agent.tools.base import MoviePilotTool
from app.sdk.plugins import PluginManager
from .schemas import VocabularyAnnotatingToolInput, QueryAnnotationTasksToolInput, Task


class VocabularyAnnotatingTool(MoviePilotTool):
    """词汇标注工具"""

    # 工具名称
    name: str = "vocabulary_annotating_tool"
    # 工具描述
    description: str = "Add new vocabulary annotation task to plugin LexiAnnot's task queue."
    # 输入参数模型
    args_schema: Type[BaseModel] = VocabularyAnnotatingToolInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据订阅参数生成友好的提示消息"""
        skip_existing = kwargs.get("skip_existing", False)
        video_path = kwargs.get("video_path", "")
        message = f"正在添加字幕任务: {video_path!r}"
        if skip_existing:
            message += "（覆写方式：跳过已存在的字幕文件）"
        else:
            message += "（覆写方式：覆盖已存在的字幕文件）"
        return message

    async def run(self, video_path: str, skip_existing: bool = True, **kwargs) -> str:
        """
        实现工具的核心逻辑（异步方法）

        :param video_path: Path to the video file
        :param skip_existing: Whether to skip existing subtitle files
        :param kwargs: 其他参数，包含 explanation（工具使用说明）
        :return: 工具执行结果，返回字符串格式
        """
        try:
            # 执行工具逻辑
            result = await self._perform_operation(video_path, skip_existing)

            # 返回执行结果
            if not result:
                return f"成功添加词汇标注任务: {video_path!r}"
            else:
                return f"添加任务出错: {result}"
        except Exception as e:
            return f"执行失败: {str(e)}"

    async def _perform_operation(
        self, video_path: str, skip_existing: bool
    ) -> str | None:
        """内部方法，执行具体操作"""
        # 实现具体业务逻辑
        plugins = PluginManager().running_plugins
        plugin_instance = plugins.get("LexiAnnot")
        if not plugin_instance:
            return "LexiAnnot 插件未运行"
        res = await asyncio.to_thread(
            plugin_instance.add_task, video_file=video_path, skip_existing=skip_existing
        )
        if not res:
            return "任务添加失败"
        return None

class QueryAnnotationTasksTool(MoviePilotTool):
    """词汇标注任务查询工具"""

    # 工具名称
    name: str = "query_annotation_tasks_tool"
    # 工具描述
    description: str = "Query the latest vocabulary annotation tasks from plugin LexiAnnot."
    # 输入参数模型
    args_schema: Type[BaseModel] = QueryAnnotationTasksToolInput

    def get_tool_message(self, **kwargs) -> Optional[str]:
        """根据订阅参数生成友好的提示消息"""
        count = kwargs.get("count", 5)
        return f"正在查询最近的 {count} 条字幕标注任务"

    async def run(self, count: int, **kwargs) -> str:
        """
        实现工具的核心逻辑（异步方法）

        :param count: The max number of returned annotation tasks
        :param kwargs: 其他参数，包含 explanation（工具使用说明）
        :return: 工具执行结果，返回字符串格式
        """
        try:
            # 执行工具逻辑
            plugins = PluginManager().running_plugins
            plugin_instance = plugins.get("LexiAnnot")
            if not plugin_instance:
                return "LexiAnnot 插件未运行"
            total: list[Task] = plugin_instance.get_tasks()
            # Handle potential None in add_time
            total.sort(key=lambda t: t.add_time or "", reverse=True)

            tasks = total[:count]
            if not tasks:
                return "未查询到相关任务"

            result_lines = [f"最近 {len(tasks)} 条标注任务:"]
            for task in tasks:
                status_val = (
                    task.status.value
                    if hasattr(task.status, "value")
                    else str(task.status)
                )

                info = f"\n🎥 **{task.video_path}**"
                info += f"\n   ID: {task.task_id}"
                info += f"\n   Status: {status_val}"
                info += f"\n   Added: {task.add_time or 'N/A'}"
                if task.complete_time:
                    info += f"\n   Completed: {task.complete_time}"
                if task.message:
                    info += f"\n   Message: {task.message}"
                if task.statistics:
                    info += f"\n   Words: {task.statistics.total_words} | Segments: {task.statistics.total_segments}"

                result_lines.append(info)

            return "\n".join(result_lines)

        except Exception as e:
            return f"执行失败: {str(e)}"
