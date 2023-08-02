# -*- coding: utf-8 -*-
import os
import platform
import subprocess

import idc
import idaapi
import idautils


def demangle_exe_path():
    """获取demangle文件的可执行路径"""
    system = platform.system()
    if system == "Darwin":
        return '/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle'
    if system == "Windows":
        directory = os.path.split(os.path.realpath(__file__))[0]
        return directory + '/swift-demangle.exe'

    raise "Only support macOS and Windows"


def demangle(func_name_list):
    """
    调用cmd执行swift-demangle命令进行符号还原, 支持多个
    :param func_name_list: 需要还原的函数名列表
    :type func_name_list: list
    :return: 还原后名称的字符串，多个用\n分割
    :rtype: str
    """
    args = [demangle_exe_path(), "--compact"]
    args.extend(func_name_list)
    return subprocess.check_output(args, bufsize=4096)


def wrap_swift2OCMethod(funcName):
    """转换成OC风格的命名规范"""
    funcName = funcName.strip()
    # 删除返回值
    if "->" in funcName:
        funcName = funcName.split("->")[0].strip()

    funcName = funcName.replace("type metadata accessor for ", "")

    if funcName.startswith('-[') or funcName.startswith('+['):
        return funcName
    if funcName.startswith('static '):
        return "+[ " + funcName + ' ]'
    return "-[ " + funcName + ' ]'


def try2get_demangle(func_name_list):
    """ 尝试将函数符号demangle,转换失败返回None

    :param func_name_list: 函数名称
    :type func_name_list: list
    :return: 转换后的名称
    :rtype: list
    """
    mangle_name_list = demangle(func_name_list)
    if not mangle_name_list:
        return [None for _ in range(len(func_name_list))]

    result = []
    for mangle_name in mangle_name_list.strip().split("\n"):
        # 去掉末尾的\n
        mangle_name = mangle_name.strip()
        # sub函数demangle后会在函数名前加$ sub_xxx --demangle--> $sub_xxx
        if mangle_name[0] == "$":
            mangle_name = mangle_name[1:]
        # 转换失败的情况
        if "(extension in " in mangle_name or ("expression of" in mangle_name):
            mangle_name = None
        result.append(mangle_name)

    return result


class Demangle_Menu_Context(idaapi.action_handler_t):

    @classmethod
    def get_name(cls):
        return cls.__name__

    @classmethod
    def get_label(cls):
        return cls.label

    @classmethod
    def register(cls, plugin, label):
        cls.plugin = plugin
        cls.label = label
        instance = cls()
        return idaapi.register_action(idaapi.action_desc_t(
            cls.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(cls):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(cls.get_name())

    @classmethod
    def activate(cls, ctx):
        # dummy method
        return 1

    @classmethod
    def update(cls, ctx):
        try:
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            else:
                return idaapi.AST_DISABLE_FOR_FORM
        except Exception as e:
            # Add exception for main menu on >= IDA 7.0
            return idaapi.AST_ENABLE_ALWAYS


# context menu for Patcher All
class Demangle_MC_PatcherAll(Demangle_Menu_Context):
    def activate(self, ctx):
        self.plugin.patcher_all()
        return 1


# context menu for Patcher One
class Demangle_MC_PatcherOne(Demangle_Menu_Context):
    def activate(self, ctx):
        self.plugin.patcher_one()
        return 1


# context menu for About
class Demangle_MC_About(Demangle_Menu_Context):
    def activate(self, ctx):
        self.plugin.about()
        return 1


class Hooks(idaapi.UI_Hooks):
    if idaapi.IDA_SDK_VERSION >= 700:
        # IDA >= 700 right click widget popup
        def finish_populating_widget_popup(self, form, popup):
            if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, Demangle_MC_PatcherAll.get_name(), 'DemangleSwift/')
                    idaapi.attach_action_to_popup(form, popup, Demangle_MC_PatcherOne.get_name(), 'DemangleSwift/')
                    idaapi.attach_action_to_popup(form, popup, "-", 'DemangleSwift/')
                    idaapi.attach_action_to_popup(form, popup, Demangle_MC_About.get_name(), 'DemangleSwift/')
                except:
                    pass
    else:
        # IDA < 700 right click popup
        def finish_populating_tform_popup(self, form, popup):
            # We'll add our action to all "IDA View-*"s.
            # If we wanted to add it only to "IDA View-A", we could
            # also discriminate on the widget's title:
            #
            #  if idaapi.get_tform_title(form) == "IDA View-A":
            #      ...
            #
            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, Demangle_MC_PatcherAll.get_name(), 'DemangleSwift/')
                    idaapi.attach_action_to_popup(form, popup, Demangle_MC_PatcherOne.get_name(), 'DemangleSwift/')
                    idaapi.attach_action_to_popup(form, popup, "-", 'DemangleSwift/')
                    idaapi.attach_action_to_popup(form, popup, Demangle_MC_About.get_name(), 'DemangleSwift/')
                except:
                    pass


class Demangle_Swift_t(idaapi.plugin_t):
    comment = "Demangle Swift plugin for IDA Pro 7.0"
    help = "https://github.com/paradiseduo/ida-swift-demangle/issues"
    wanted_name = "Demangle Swift"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        print("Demangle Swift (v1.0) plugin has been loaded.")

        # register popup menu handlers
        try:
            Demangle_MC_PatcherAll.register(self, "demangle swift of all functions")
            Demangle_MC_PatcherOne.register(self, "demangle swift of current functions")
            Demangle_MC_About.register(self, "About")
        except:
            pass

        # Add ui hook
        self.ui_hook = Hooks()
        self.ui_hook.hook()

        return idaapi.PLUGIN_OK

    def term(self):
        return idaapi.PLUGIN_OK

    @staticmethod
    def creat_all_func():
        """获取所有需要转换的函数，目前只转换以_$s、$s开头的函数"""
        all_func_dict = {}
        # 获取所有函数
        for addr in idautils.Functions():
            name = idc.GetFunctionName(addr)
            # only parse of start with：_$s $s
            if not (name.startswith("_$s") or name.startswith("$s")):
                continue
            # 函数以$开头因为是特殊符号会被IDA重命名_$
            if name[:1] == "_":
                name = name[1:]
            # 保存地址
            all_func_dict[addr] = {"addr": addr, "name": name}

        return all_func_dict

    @staticmethod
    def creat_cur_func():
        """获取当前需要转换的函数：根据当前地址获取所在函数名"""
        name = idc.get_func_name(idc.here())
        addr = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)
        # 函数以$开头因为是特殊符号会被IDA重命名_$
        if name[:1] == "_":
            name = name[1:]
        return {addr: {"addr": addr, "name": name}}

    @staticmethod
    def demangle_all_func(all_func_dict):
        """demangle of all functions"""
        # 单个转换会造成IDA卡死，所有需要批量转换
        # 一次转换函数的数量，设置太大可能会崩溃，太小会造成IDA卡死，建议设置范围 100-200
        step = 100
        keys = all_func_dict.keys()
        for i in range(0, len(keys), step):
            item_keys = keys[i: i + step]
            item_name_list = [all_func_dict[key]['name'] for key in item_keys]
            demangle_name_list = try2get_demangle(item_name_list)
            for key, demangle_name in zip(item_keys, demangle_name_list):
                old_name = all_func_dict[key]['name']
                if demangle_name and old_name != demangle_name:
                    all_func_dict[key]['demangle'] = demangle_name
                # else:
                # 删除没有转换成功的,加快遍历
                # del all_func_dict[key]

    def patcher(self, turn_all=False):
        if turn_all:
            all_func_dict = self.creat_all_func()
        else:
            all_func_dict = self.creat_cur_func()

        if len(all_func_dict) == 0:
            print("No function of demangle was found!")
            return
        print("len(all_func_dict):", len(all_func_dict))

        self.demangle_all_func(all_func_dict)
        suc_num = 0
        for addr, info in all_func_dict.items():
            demangle_name = info.get('demangle')
            if not demangle_name:
                continue
            old_name = info['name']
            # 转成obc的命名风格
            obc_name = wrap_swift2OCMethod(demangle_name)
            # rename
            idc.MakeNameEx(addr, obc_name, idc.SN_NOCHECK | idc.SN_NOWARN)
            # 注释
            idc.SetFunctionCmt(addr, "%s Demangle-->\n%s" % (old_name, demangle_name), 1)
            suc_num += 1

        print("Demangle Swift Over! The number of Renamed Functions is: ", suc_num)

    def patcher_all(self):
        self.patcher(turn_all=True)

    def patcher_one(self):
        self.patcher()

    @staticmethod
    def about():
        print("Demangle Swift Use:\nchoose function to run!")

    def run(self, arg):
        # 无参数，默认转换所有函数
        self.patcher_all()


# register IDA plugin
def PLUGIN_ENTRY():
    return Demangle_Swift_t()
