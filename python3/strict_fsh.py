#!/usr/bin/python3

# strict_fsh.py - strict file system hierarchy
#
# Copyright (c) 2020-2022 Fpemud <fpemud@sina.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
strict_fsh

@author: Fpemud
@license: GPLv3 License
@contact: fpemud@sina.com
"""

import os
import pwd
import grp
import stat
import unicodedata


__author__ = "fpemud@sina.com (Fpemud)"
__version__ = "0.0.1"


WILDCARDS_LAYOUT = 1             # FSH layout files
WILDCARDS_SYSTEM = 2             # system files
WILDCARDS_SYSTEM_BOOT = 3        # system boot files, subset of system files
WILDCARDS_SYSTEM_CFG = 4         # system config files, subset of system files
WILDCARDS_SYSTEM_DATA = 5        # system data files, subset of system files
WILDCARDS_SYSTEM_CACHE = 6       # system cache files, subset of system files
WILDCARDS_USER = 7               # user files (including root user)
WILDCARDS_USER_CACHE = 8         # user cache files, subset of user files
WILDCARDS_USER_TRASH = 9         # trash files, subset of user files
WILDCARDS_RUNTIME = 10           # runtime files


def merge_wildcards(wildcards1, wildcards2):
    assert all([_HelperWildcard.is_pattern_inc_or_exc(w) for w in wildcards1])        # FIXME
    return wildcards1 + wildcards2


def deduct_wildcards(wildcards1, wildcards2):
    assert all([_HelperWildcard.is_pattern_inc_or_exc(w) for w in wildcards2])        # FIXME
    ret = []
    for w in wildcards2:
        ret.append("- " + w[2:])
    return ret + wildcards1


def finalize_wildcards(wildcards):
    ret = []
    while True:
        for i in range(0, len(wildcards)):
            w = wildcards[i]

            # wildcard overlapped by a previous wildcard, delete
            if True:
                for w2 in ret:
                    if wildcards_match(w[2:], w2):
                        w = None
                        break
                if w is None:
                    continue

            # wildcard overlapped by a later, consecutive, with-same-direction wildcard, delete
            if True:
                for w2 in wildcards[i+1:]:
                    if w2.startswith(w[:2]):
                        if wildcards_match(w[2:], w2):
                            w = None
                            break
                    else:
                        break
                if w is None:
                    continue

            # -wildcard must overlap/be-overlapped-by one of a later +wildcard, if not, delete
            if w.startswith("- "):
                bFound = False
                for w2 in wildcards[i+1:]:
                    if w2.startswith("+ "):
                        if wildcards_match(w[2:], w2) or wildcards_match(w2[2:], w):
                            bFound = True
                            break
                if not bFound:
                    continue

            ret.append(w)

        if len(ret) < len(wildcards):
            wildcards = ret
            ret = []
            continue

        return ret


def wildcards_match(name, wildcards):
    """
    Test whether NAME matches WILDCARDS.

    strict_fsh wildcard specification:
    o      '+ ' prefix means inclusion, '- ' prefix means exclusion, wildcards are order sensitive.
    o      use '**' to match anything, including slashes, but only trailing "dir_name/**" is allowed.
    o      a trailing "dir_name/***" will match both the directory (as if "dir_name/" had been specified) and everything in the directory (as if "dir_name/**" had been specified).
    o      wildcard must begin with a '/'.
    """

    _HelperWildcard.check_patterns(wildcards)

    for w in wildcards:
        if _HelperWildcard.match_pattern(name, w):
            return _HelperWildcard.is_pattern_inc_or_exc(w)
    return False


def wildcards_filter(names, wildcards):
    """Return the subset of the list NAMES that match WILDCARDS."""

    _HelperWildcard.check_patterns(wildcards)

    result = []
    for name in names:
        for w in wildcards:
            if _HelperWildcard.match_pattern(name, w):
                if _HelperWildcard.is_pattern_inc_or_exc(w):
                    result.append(name)
                else:
                    break
    return result


class RootFs:

    """
    We comply with FHS (https://refspecs.linuxfoundation.org/fhs.shtml) but have some extra rules:
      * Fedora UsrMerge (https://fedoraproject.org/wiki/Features/UsrMove)
      * FreeDesktop Trash Specification (https://freedesktop.org/wiki/Specifications/trash-spec)
      * /etc/hostname for hostname configuration
      * /var/empty as a system wide empty directory
      * optional toolchain directories in /usr
      * optional per-user runtime directory /run/user/*

    Q: Why remove /var/lock instead of keep it as a symlink?
    A: /var/lock symlink points to /run/lock, to make /var/lock not dangling, /run/lock has to be created dynamically on every system boot.
       We choose to remove /var/lock totally to avoid this extra complexity.

    Q: Why not also remove /var/run?
    A: At least, according to "man utmp", utmp file is still located in /var/run/utmp.
    """

    def __init__(self, dirPrefix="/"):
        self._helper = _HelperPrefixedDirOp(self)
        self._dirPrefix = dirPrefix

    def get_wildcards(self, user=None, wildcards_flag=None):
        if wildcards_flag == WILDCARDS_LAYOUT:
            assert user is None
            return self._getWildcardsLayout()
        if wildcards_flag == WILDCARDS_SYSTEM:
            assert user is None
            ret = []
            ret += self._getWildcardsSystemBasic()
            ret += self._getWildcardsSystemCfg()
            ret += self._getWildcardsSystemData()
            ret += self._getWildcardsSystemCache()
            return ret
        if wildcards_flag == WILDCARDS_SYSTEM_BOOT:
            assert user is None
            return self._getWildcardsSystemBoot()
        if wildcards_flag == WILDCARDS_SYSTEM_CFG:
            assert user is None
            return self._getWildcardsSystemCfg()
        if wildcards_flag == WILDCARDS_SYSTEM_DATA:
            assert user is None
            return self._getWildcardsSystemData()
        if wildcards_flag == WILDCARDS_SYSTEM_CACHE:
            assert user is None
            return self._getWildcardsSystemCache()
        if wildcards_flag == WILDCARDS_USER:
            return self._getWildcardsUser(user)
        if wildcards_flag == WILDCARDS_USER_CACHE:
            return self._getWildcardsUserCache(user)
        if wildcards_flag == WILDCARDS_USER_TRASH:
            return self._getWildcardsUserTrash(user)
        if wildcards_flag == WILDCARDS_RUNTIME:
            assert user is None
            return self._getWildcardsRuntime()
        assert False

    def wildcards_glob(self, wildcards):
        _HelperWildcard.check_patterns(wildcards)
        return self._wildcardsGlob(wildcards)

    def check(self, deep_check=False, auto_fix=False, error_callback=None):
        self._bAutoFix = auto_fix
        self._errCb = error_callback if error_callback is not None else _doNothing
        self._record = set()
        try:
            self._doCheckLayout()
            self._doCheckSystemFiles()
            if deep_check:
                self._doCheckSystemDataFiles()
                self._doCheckUserDataFiles()
        finally:
            del self._record
            del self._errCb
            del self._bAutoFix

    def _doCheckLayout(self):
        # /
        self._checkDir("/", 0o0755, "root", "root")

        # /bin
        self._checkSymlink("/bin", "usr/bin", "root", "root")

        # /boot
        self._checkDir("/boot", 0o0755, "root", "root")

        # /dev
        self._checkDir("/dev", 0o0755, "root", "root")

        # /etc
        self._checkDir("/etc", 0o0755, "root", "root")

        # /etc/hostname
        self._checkFile("/etc/hostname",  0o0644, "root", "root")

        # /home
        self._checkDir("/home", 0o0755, "root", "root")
        for fn in self._fullListDir("/home"):
            userName = os.path.basename(fn)
            self._checkDir(fn, 0o0700, userName, userName)

        # /lib
        self._checkSymlink("/lib", "usr/lib", "root", "root")

        # /lib64
        self._checkSymlink("/lib64", "usr/lib64", "root", "root")

        # /mnt
        self._checkDir("/mnt", 0o0755, "root", "root")

        # /opt
        self._checkDir("/opt", 0o0755, "root", "root")

        # /proc
        self._checkDir("/proc", 0o0555, "root", "root")

        # /root
        self._checkDir("/root", 0o0700, "root", "root")

        # /run
        self._checkDir("/run", 0o0755, "root", "root")
        if True:
            self._checkDir("/run/lock", 0o0755, "root", "root")
            if os.path.exists("/run/user"):
                self._checkDir("/run/user", 0o0755, "root", "root")
                for fn in self._fullListDir("/run/user"):
                    userId = int(os.path.basename(fn))
                    self._checkDir(fn, 0o0700, userId, userId)      # user id is used as directory name

        # /sbin
        self._checkSymlink("/sbin", "usr/bin", "root", "root")

        # /sys
        self._checkDir("/sys", 0o0555, "root", "root")

        # /tmp
        self._checkDir("/tmp", 0o1777, "root", "root")              # /tmp has stick bit

        # /usr
        self._checkDir("/usr", 0o0755, "root", "root")

        # /usr/bin
        self._checkDir("/usr/bin", 0o0755, "root", "root")

        # /usr/games
        if self._exists("/usr/games"):
            self._checkDir("/usr/games", 0o0755, "root", "root")
            if self._exists("/usr/games/bin"):
                self._checkDir("/usr/games/bin", 0o0755, "root", "root")

        # /usr/include
        if self._exists("/usr/include"):
            self._checkDir("/usr/include", 0o0755, "root", "root")

        # /usr/lib
        self._checkDir("/usr/lib", 0o0755, "root", "root")

        # /usr/lib64
        self._checkDir("/usr/lib64", 0o0755, "root", "root")

        # /usr/libexec
        self._checkDir("/usr/libexec", 0o0755, "root", "root")

        # /usr/local
        if self._exists("/usr/local"):
            self._checkDir("/usr/local", 0o0755, "root", "root")
            if self._exists("/usr/local/bin"):
                self._checkDir("/usr/local/bin", 0o0755, "root", "root")
            if self._exists("/usr/local/etc"):
                self._checkDir("/usr/local/etc", 0o0755, "root", "root")
            if self._exists("/usr/local/games"):
                self._checkDir("/usr/local/games", 0o0755, "root", "root")
            if self._exists("/usr/local/include"):
                self._checkDir("/usr/local/include", 0o0755, "root", "root")
            if self._exists("/usr/local/lib"):
                self._checkDir("/usr/local/lib", 0o0755, "root", "root")
            if self._exists("/usr/local/lib64"):
                self._checkDir("/usr/local/lib64", 0o0755, "root", "root")
            if self._exists("/usr/local/man"):
                self._checkDir("/usr/local/man", 0o0755, "root", "root")
            if self._exists("/usr/local/sbin"):
                self._checkDir("/usr/local/sbin", 0o0755, "root", "root")
            if self._exists("/usr/local/share"):
                self._checkDir("/usr/local/share", 0o0755, "root", "root")
            if self._exists("/usr/local/src"):
                self._checkDir("/usr/local/src", 0o0755, "root", "root")

        # /usr/sbin
        self._checkSymlink("/usr/sbin", "bin", "root", "root")

        # /usr/share
        self._checkDir("/usr/share", 0o0755, "root", "root")

        # /usr/src
        if self._exists("/usr/src"):
            self._checkDir("/usr/src", 0o0755, "root", "root")

        # toolchain directories in /usr
        for fn in self._fullListDir("/usr"):
            if _isToolChainName(os.path.basename(fn)):
                self._checkDir(fn, 0o0755, "root", "root")

        # /var
        self._checkDir("/var", 0o0755, "root", "root")

        # /var/cache
        if self._exists("/var/cache"):
            self._checkDir("/var/cache", 0o0755, "root", "root")

        # /var/db
        if self._exists("/var/db"):
            self._checkDir("/var/db", 0o0755, "root", "root")

        # /var/empty
        self._checkDir("/var/empty", 0o0755, "root", "root")
        self._checkDirIsEmpty("/var/empty")

        # /var/games
        if self._exists("/var/games"):
            self._checkDir("/var/games", 0o0755, "root", "root")
            self._checkDirIsEmpty("/var/games")                       # this directory is deprecated

        # /var/lib
        if self._exists("/var/lib"):
            self._checkDir("/var/lib", 0o0755, "root", "root")

        # /var/log
        if self._exists("/var/log"):
            self._checkDir("/var/log", 0o0755, "root", "root")

        # /var/run
        self._checkSymlink("/var/run", "../run", "root", "root")

        # /var/spool
        if self._exists("/var/spool"):
            self._checkDir("/var/spool", 0o0755, "root", "root")

        # /var/tmp
        self._checkDir("/var/tmp", 0o1777, "root", "root")            # /var/tmp has stick bit

        # /var/www
        if self._exists("/var/www"):
            self._checkDir("/var/www", 0o0775, "root", "root")
            self._checkDirIsEmpty("/var/www")                         # this directory is deprecated

        # redundant files
        self._checkNoRedundantFilesWithoutRecursion("/")
        self._checkNoRedundantFilesWithoutRecursion("/usr")
        if self._exists("/usr/local"):
            self._checkNoRedundantFilesWithoutRecursion("/usr/local")
        self._checkNoRedundantFilesWithoutRecursion("/var")

    def _doCheckSystemFiles(self):
        for fn in self._wildcardsGlob(self._getWildcardsSystemBasic()):
            self._batchCheckBasic(fn)

    def _doCheckSystemDataFiles(self):
        for fn in self._wildcardsGlob(self._getWildcardsSystemData()):
            self._batchCheckBasic(fn)

    def _doCheckUserDataFiles(self):
        for fn in self._fullListDir("/home"):
            userName = os.path.basename(fn)
            for fn in self._wildcardsGlob(self._getWildcardsUser(userName)):
                self._batchCheckBasic(fn)
                self._batchCheckOwnerGroup(fn, userName, userName)

    def _getWildcardsLayout(self):
        ret = [
            "+ /",
            "+ /bin",             # symlink
            "+ /boot",
            "+ /dev",
            "+ /etc",
            "+ /etc/hostname",
            "+ /home",
            "+ /lib",             # symlink
            "+ /lib64",           # symlink
            "+ /mnt",
            "+ /opt",
            "+ /proc",
            "+ /root",
            "+ /run",
            "+ /sbin",            # symlink
            "+ /sys",
            "+ /tmp",
            "+ /usr",
            "+ /usr/bin",
        ]
        if self._exists("/usr/games"):
            ret.append("+ /usr/games")
            if self._exists("/usr/games/bin"):
                ret.append("+ /usr/games/bin")
        if self._exists("/usr/include"):
            ret.append("+ /usr/include")
        ret += [
            "+ /usr/lib",
            "+ /usr/lib64",
            "+ /usr/libexec",
        ]
        if self._exists("/usr/local"):
            ret.append("+ /usr/local")
            if self._exists("/usr/local/bin"):
                ret.append("+ /usr/local/bin")
            if self._exists("/usr/local/etc"):
                ret.append("+ /usr/local/etc")
            if self._exists("/usr/local/games"):
                ret.append("+ /usr/local/games")
            if self._exists("/usr/local/include"):
                ret.append("+ /usr/local/include")
            if self._exists("/usr/local/lib"):
                ret.append("+ /usr/local/lib")
            if self._exists("/usr/local/lib64"):
                ret.append("+ /usr/local/lib64")
            if self._exists("/usr/local/man"):
                ret.append("+ /usr/local/man")
            if self._exists("/usr/local/sbin"):
                ret.append("+ /usr/local/sbin")
            if self._exists("/usr/local/share"):
                ret.append("+ /usr/local/share")
        if True:
            ret.append("+ /usr/opt")                        # FIXME: make /opt -> /usr/opt ?
            if self._exists("/usr/opt/bin"):
                ret.append("+ /usr/opt/bin")
        ret += [
            "+ /usr/sbin",        # symlink
            "+ /usr/share",
        ]
        for fn in self._fullListDir("/usr"):
            if _isToolChainName(os.path.basename(fn)):
                ret.append("+ %s" % (fn))
        ret += [
            "+ /var",
        ]
        if self._exists("/var/cache"):
            ret.append("+ /var/cache")
        if self._exists("/var/db"):
            ret.append("+ /var/db")
        ret += [
            "+ /var/empty",
        ]
        if self._exists("/var/lib"):
            ret.append("+ /var/lib")
        if self._exists("/var/log"):
            ret.append("+ /var/log")
        ret += [
            "+ /var/run",         # symlink
            "+ /var/tmp",
        ]
        return ret

    def _getWildcardsSystemBasic(self):
        return [
            "+ /boot/**",
            "+ /usr/**",
            "+ /opt/**",
        ]

    def _getWildcardsSystemBoot(self):
        return [
            "+ /boot/**",
            "+ /usr/lib/modules/***",
            "+ /usr/lib/firmware/***",
        ]

    def _getWildcardsSystemCfg(self):
        return [
            "+ /etc/**",
        ]

    def _getWildcardsSystemData(self):
        ret = []
        if self._exists("/var/db"):
            ret.append("+ /var/db/**")
        if self._exists("/var/lib"):
            ret.append("+ /var/lib/**")
        if self._exists("/var/log"):
            ret.append("+ /var/log/**")
        return ret

    def _getWildcardsSystemCache(self):
        ret = []
        if self._exists("/var/cache"):
            ret.append("+ /var/cache/**")
        return ret

    def _getWildcardsUser(self, user):
        ret = []
        if user is None or user == "root":
            ret.append("+ /root/**")                # "/root" belongs to FSH layout
        for fn in self._fullListDir("/home"):
            if user is None or user == os.path.basename(fn):
                ret.append("+ %s/***" % (fn))       # "/home/X" belongs to user files
        assert len(ret) > 0
        return ret

    def _getWildcardsUserCache(self, user):
        ret = []
        if user is None or user == "root":
            if self._exists("/root/.cache"):
                ret.append("+ /root/.cache/**")
        for fn in self._fullListDir("/home"):
            if user is None or user == os.path.basename(fn):
                if self._exists("%s/.cache" % (fn)):
                    ret.append("+ %s/.cache/**" % (fn))
        assert len(ret) > 0
        return ret

    def _getWildcardsUserTrash(self, user):
        ret = []
        if user is None or user == "root":
            if self._exists("/var/.Trash-0"):
                ret.append("+ /var/.Trash-0/**")
        for fn in self._fullListDir("/home"):
            if user is None or user == os.path.basename(fn):
                if self._exists("%s/.local/share/Trash" % (fn)):
                    ret.append("+ %s/.local/share/Trash/**" % (fn))
        assert len(ret) > 0
        return ret

    def _getWildcardsRuntime(self):
        ret = [
            "+ /dev/**",
            "+ /mnt/**",
            "+ /proc/**",
            "+ /run/**",
            "+ /sys/**",
            "+ /tmp/**",
        ]
        if self._exists("/var/spool"):
            ret.append("+ /var/spool/**")
        ret += [
            "+ /var/tmp/**",
        ]
        return ret

    def _wildcardsGlob(self, wildcards):
        wildcards2 = []
        for w in wildcards:
            w2 = w[:2] + os.path.join(self._dirPrefix, w[3:])
            wildcards2.append(w2)

        ret = []
        self._wildcardsGlobImpl(self._dirPrefix, wildcards2, ret)
        ret = ["/" + x[len(self._dirPrefix):] for x in ret]
        return ret

    def _wildcardsGlobImpl(self, curPath, wildcards, result):
        if os.path.isdir(curPath) and not os.path.islink(curPath):
            bRecorded = False
            bRecursive = False
            for w in wildcards:
                if _HelperWildcard.match_pattern(curPath, w):
                    if _HelperWildcard.is_pattern_inc_or_exc(w):
                        if not bRecorded:
                            result.append(curPath)
                            bRecorded = True
                        if w.endswith("/***") or w.endswith("/**"):
                            bRecursive = True
                            break
                    else:
                        bRecorded = True
                        if w.endswith("/***") or w.endswith("/**"):
                            break
                else:
                    if _HelperWildcard.is_pattern_inc_or_exc(w) and w[2:].startswith(_pathAddSlash(curPath)):
                        bRecursive = True
                        if bRecorded:
                            break
            if bRecursive:
                for fn in os.listdir(curPath):
                    self._wildcardsGlobImpl(os.path.join(curPath, fn), wildcards, result)
        else:
            for w in wildcards:
                if _HelperWildcard.match_pattern(curPath, w):
                    if _HelperWildcard.is_pattern_inc_or_exc(w):
                        result.append(curPath)
                    return

    def __getattr__(self, attr):
        return getattr(self._helper, attr)


class PreMountRootFs:

    def __init__(self, dir, mounted_boot=True, mounted_etc=True, mounted_home=True, mounted_var=True):
        self._helper = _HelperPrefixedDirOp(self)
        self._dirPrefix = dir
        self._bMountBoot = mounted_boot     # /boot is mounted
        self._bMountEtc = mounted_etc       # /etc is mounted
        self._bMountHome = mounted_home     # /root, /home/* are mounted
        self._bMountVar = mounted_var       # /var/cache, /var/db, /var/games, /var/lib, /var/log, /var/spool, /var/tmp, /var/www are mounted

    def check(self, auto_fix=False, error_callback=None):
        self._bAutoFix = auto_fix
        self._errCb = error_callback if error_callback is not None else _doNothing
        self._record = set()
        try:
            # /bin
            self._checkUsrMergeSymlink("/bin", "usr/bin")

            # /boot
            self._checkDir("/boot")
            if self._bMountBoot:
                self._checkDirIsEmpty("/boot")

            # /dev
            self._checkDir("/dev")
            self._checkDevDirContent("/dev", [
                ("console", "c", 5, 1, 0o0600, "root", "root"),
                ("null",    "c", 1, 3, 0o0666, "root", "root"),
            ])

            # /etc
            self._checkDir("/etc")
            if self._bMountEtc:
                self._checkDirIsEmpty("/etc")

            # /home
            self._checkDir("/home")
            if self._bMountHome:
                for fn in self._fullListDir("/home"):
                    self._checkDirIsEmpty(fn)

            # /lib
            self._checkUsrMergeSymlink("/lib", "usr/lib")

            # /lib64
            self._checkUsrMergeSymlink("/lib64", "usr/lib64")

            # /mnt
            self._checkDir("/mnt")
            self._checkDirIsEmpty("/mnt")

            # /opt
            self._checkDir("/opt")

            # /proc
            self._checkDir("/proc")
            self._checkDirIsEmpty("/proc")

            # /root
            self._checkDir("/root")
            if self._bMountHome:
                self._checkDirIsEmpty("/root")

            # /run
            self._checkDir("/run")
            self._checkDirIsEmpty("/run")

            # /sbin
            self._checkUsrMergeSymlink("/sbin", "usr/bin")

            # /sys
            self._checkDir("/sys")
            self._checkDirIsEmpty("/sys")

            # /tmp
            self._checkDir("/tmp")
            self._checkDirIsEmpty("/tmp")

            # /usr
            self._checkDir("/usr")

            # /usr/bin
            self._checkDir("/usr/bin")

            # /usr/games
            if self._exists("/usr/games"):
                self._checkDir("/usr/games")
                if self._exists("/usr/games/bin"):
                    self._checkDir("/usr/games/bin")

            # /usr/include
            if self._exists("/usr/include"):
                self._checkDir("/usr/include")

            # /usr/lib
            self._checkDir("/usr/lib")

            # /usr/lib64
            self._checkDir("/usr/lib64")

            # /usr/libexec
            self._checkDir("/usr/libexec")

            # /usr/local
            if self._exists("/usr/local"):
                self._checkDir("/usr/local")
                if self._exists("/usr/local/bin"):
                    self._checkDir("/usr/local/bin")
                if self._exists("/usr/local/etc"):
                    self._checkDir("/usr/local/etc")
                if self._exists("/usr/local/games"):
                    self._checkDir("/usr/local/games")
                if self._exists("/usr/local/include"):
                    self._checkDir("/usr/local/include")
                if self._exists("/usr/local/lib"):
                    self._checkDir("/usr/local/lib")
                if self._exists("/usr/local/lib64"):
                    self._checkDir("/usr/local/lib64")
                if self._exists("/usr/local/man"):
                    self._checkDir("/usr/local/man")
                if self._exists("/usr/local/sbin"):
                    self._checkDir("/usr/local/sbin")
                if self._exists("/usr/local/share"):
                    self._checkDir("/usr/local/share")
                if self._exists("/usr/local/src"):
                    self._checkDir("/usr/local/src")

            # /usr/sbin
            self._checkUsrMergeSymlink("/usr/sbin", "bin")

            # /usr/share
            self._checkDir("/usr/share")

            # /usr/src
            if self._exists("/usr/src"):
                self._checkDir("/usr/src")

            # toolchain directories in /usr
            for fn in self._fullListDir("/usr"):
                if _isToolChainName(os.path.basename(fn)):
                    self._checkDir(fn)

            # /var
            self._checkDir("/var")

            # /var/cache
            if self._exists("/var/cache"):
                self._checkDir("/var/cache")
                if self._bMountVar:
                    self._checkDirIsEmpty("/var/cache")

            # /var/db
            if self._exists("/var/db"):
                self._checkDir("/var/db")
                if self._bMountVar:
                    self._checkDirIsEmpty("/var/db")

            # /var/empty
            self._checkDir("/var/empty")
            self._checkDirIsEmpty("/var/empty")

            # /var/games
            if self._exists("/var/games"):
                self._checkDir("/var/games")
                if self._bMountVar:
                    self._checkDirIsEmpty("/var/games")

            # /var/lib
            if self._exists("/var/lib"):
                self._checkDir("/var/lib")
                if self._bMountVar:
                    self._checkDirIsEmpty("/var/lib")

            # /var/log
            if self._exists("/var/log"):
                self._checkDir("/var/log")
                if self._bMountVar:
                    self._checkDirIsEmpty("/var/log")

            # /var/run
            self._checkSymlink("/var/run", "../run")

            # /var/spool
            if self._exists("/var/spool"):
                self._checkDir("/var/spool")
                if self._bMountVar:
                    self._checkDirIsEmpty("/var/spool")

            # /var/tmp
            self._checkDir("/var/tmp")
            if self._bMountVar:
                self._checkDirIsEmpty("/var/tmp")

            # /var/www
            if self._exists("/var/www"):
                self._checkDir("/var/www")
                if self._bMountVar:
                    self._checkDirIsEmpty("/var/www")

            # redundant files
            self._checkNoRedundantFilesWithoutRecursion("/")
            self._checkNoRedundantFilesWithoutRecursion("/dev")
            self._checkNoRedundantFilesWithoutRecursion("/usr")
            if self._exists("/usr/local"):
                self._checkNoRedundantFilesWithoutRecursion("/usr/local")
            self._checkNoRedundantFilesWithoutRecursion("/var")
        finally:
            del self._record
            del self._bAutoFix

    def __getattr__(self, attr):
        return getattr(self._helper, attr)


class WildcardError(Exception):
    pass


class MoveDirError(Exception):
    pass


class _HelperWildcard:

    @staticmethod
    def check_patterns(wildcards):
        for w in wildcards:
            if not w.startswith("+ ") and not w.startswith("- "):
                raise WildcardError("invalid wildcard \"%s\"" % (w))
            if len(w) < 3 or w[2] != '/':
                raise WildcardError("invalid wildcard \"%s\"" % (w))
            if "*" in w and not w.endswith("/***") and not w.endswith("/**"):
                raise WildcardError("invalid wildcard \"%s\"" % (w))

    @staticmethod
    def match_pattern(name, wildcard):
        p = wildcard[2:]
        if p.endswith("/***"):
            p = os.path.dirname(p)
            if name == p or name.startswith(_pathAddSlash(p)):
                return True
        elif p.endswith("/**"):
            p = os.path.dirname(p)
            if name.startswith(_pathAddSlash(p)):
                return True
        else:
            if name == p:
                return True
        return False

    @staticmethod
    def is_pattern_inc_or_exc(wildcard):
        return wildcard.startswith("+ ")


class _HelperPrefixedDirOp:

    # we need self.p._dirPrefix, self.p._bAutoFix, self.p._record, self.p._errCb

    def __init__(self, parent):
        self.p = parent

    def _exists(self, fn):
        assert self.__validPath(fn)

        return os.path.lexists(self.__fn2fullfn(fn))

    def _fullListDir(self, fn, recursive=False):
        assert self.__validPath(fn)

        ret = []
        for i in os.listdir(self.__fn2fullfn(fn)):
            ifn = os.path.join(fn, i)
            ret.append(ifn)
            if recursive:
                fullifn = self.__fn2fullfn(ifn)
                if not os.path.islink(fullifn) and os.path.isdir(fullifn):
                    ret += self._fullListDir(ifn, True)
        return ret

    def _checkDir(self, fn, mode=None, owner=None, group=None):
        assert self.__validPath(fn)

        fullfn = self.__fn2fullfn(fn)

        if not os.path.lexists(fullfn):
            if self.p._bAutoFix:
                os.mkdir(fullfn)
            else:
                self.p._errCb("\"%s\" does not exist." % (fn))
                return

        self.p._record.add(fn)

        if os.path.islink(fullfn) or not os.path.isdir(fullfn):
            # no way to autofix
            self.p._errCb("\"%s\" is invalid." % (fn))
            return

        if mode is not None:
            self.__checkMode(fn, fullfn, mode)
        if owner is not None:
            self.__checkOwnerGroup(fn, fullfn, owner, group)

    def _checkFile(self, fn, mode=None, owner=None, group=None):
        assert self.__validPath(fn)

        fullfn = self.__fn2fullfn(fn)

        if not os.path.lexists(fullfn):
            # no way to autofix
            self.p._errCb("\"%s\" does not exist." % (fn))
            return

        self.p._record.add(fn)

        if os.path.islink(fullfn) or not os.path.isfile(fullfn):
            # no way to autofix
            self.p._errCb("\"%s\" is invalid." % (fn))
            return

        if mode is not None:
            self.__checkMode(fn, fullfn, mode)
        if owner is not None:
            self.__checkOwnerGroup(fn, fullfn, owner, group)

    def _checkSymlink(self, fn, target, owner=None, group=None):
        assert self.__validPath(fn)

        fullfn = self.__fn2fullfn(fn)

        if not os.path.lexists(fullfn):
            if self.p._bAutoFix:
                os.symlink(target, fullfn)
            else:
                self.p._errCb("\"%s\" does not exist." % (fn))
                return

        self.p._record.add(fn)

        if not os.path.islink(fullfn):
            # no way to autofix
            self.p._errCb("\"%s\" is invalid." % (fn))
            return

        if os.readlink(fullfn) != target:
            if self.p._bAutoFix:
                os.unlink(fullfn)
                os.symlink(target, fullfn)
            else:
                self.p._errCb("\"%s\" is invalid." % (fn))
                return

        if owner is not None:
            self.__checkOwnerGroup(fn, fullfn, owner, group)

    def _checkDevDirContent(self, devDir, nodeInfoList):
        assert self.__validPath(devDir)
        assert all([not x[0].startswith("/") and not x[0].endswith("/") for x in nodeInfoList])

        for nodeName, devType, major, minor, mode, owner, group in nodeInfoList:
            fn = os.path.join(devDir, nodeName)
            fullfn = self.__fn2fullfn(fn)

            # check file existence
            if not os.path.lexists(fullfn):
                if self.p._bAutoFix:
                    _makeDeviceNodeFile(fullfn, devType, major, minor, mode, owner, group)
                else:
                    self.p._errCb("\"%s\" does not exist." % (fn))
                    continue

            s = os.lstat(fullfn)

            # check type
            if devType == "b":
                if not stat.S_ISBLK(s.st_mode):
                    if self.p._bAutoFix:
                        os.remove(fullfn)
                        _makeDeviceNodeFile(fullfn, devType, major, minor, mode, owner, group)
                    else:
                        self.p._errCb("\"%s\" is not a block special device file." % (fn))
                        continue
            elif devType == "c":
                if not stat.S_ISCHR(s.st_mode):
                    if self.p._bAutoFix:
                        os.remove(fullfn)
                        _makeDeviceNodeFile(fullfn, devType, major, minor, mode, owner, group)
                    else:
                        self.p._errCb("\"%s\" is not a character special device file." % (fn))
                        continue
            else:
                assert False

            # check major and minor
            if os.major(s.st_rdev) != major or os.minor(s.st_rdev) != minor:
                if self.p._bAutoFix:
                    os.remove(fullfn)
                    _makeDeviceNodeFile(fullfn, devType, major, minor, mode, owner, group)
                else:
                    self.p._errCb("\"%s\" has invalid major and minor number." % (fn))
                    continue

            # check mode, owner and group
            self.__checkMode(fn, fullfn, mode)
            self.__checkOwnerGroup(fn, fullfn, owner, group)

        # redundant files
        keepList = [os.path.join(devDir, x[0]) for x in nodeInfoList]
        for fn in reversed(self._fullListDir(devDir, recursive=True)):
            if fn in keepList:
                continue

            if self.p._bAutoFix:
                fullfn = self.__fn2fullfn(fn)
                if os.path.islink(fullfn) or not os.path.isdir(fullfn):
                    # remove redundant file
                    os.remove(fullfn)
                else:
                    # remove redundant directory
                    # files are iterated before their parent directory using reversed()
                    try:
                        os.rmdir(fullfn)
                    except OSError as e:
                        if e.errno == 39:
                            # OSError: [Errno 39] Directory not empty
                            self.p._errCb("Directory \"%s\" should not exist but has valid file(s) in it." % (fn))
                        else:
                            raise
            else:
                self.p._errCb("\"%s\" should not exist." % (fn))

        # record files
        for fn in self._fullListDir(devDir, recursive=True):
            self.p._record.add(fn)

    def _checkUsrMergeSymlink(self, fn, target, owner=None, group=None):
        assert self.__validPath(fn)

        fullfn = self.__fn2fullfn(fn)
        fullTarget = os.path.join(os.path.dirname(fullfn), target)

        if not os.path.lexists(fullfn):
            if self.p._bAutoFix:
                os.symlink(target, fullfn)
            else:
                self.p._errCb("\"%s\" does not exist." % (fn))
                return

        self.p._record.add(fn)

        if not _isRealDir(fullTarget):
            # no way to autofix
            self.p._errCb("\"%s\" is invalid." % (fullTarget))
            return

        if not os.path.islink(fullfn):
            if _isRealDir(fullfn):
                ret = _HelperUsrMerge.compare_dir(fullfn, fullTarget)
                if len(ret) == 0:
                    _HelperUsrMerge.move_dir(fullfn, fullTarget)
                    os.symlink(target, fullfn)
                else:
                    self.p._errCb("Directory \"%s\" and \"%s\" has common files, no way to combine them." % (fn, target))
                    return
            else:
                # no way to autofix
                self.p._errCb("\"%s\" is invalid." % (fullTarget))
                return

        if os.readlink(fullfn) != target:
            if self.p._bAutoFix:
                os.unlink(fullfn)
                os.symlink(target, fullfn)
            else:
                self.p._errCb("\"%s\" is invalid." % (fn))
                return

        if owner is not None:
            self.__checkOwnerGroup(fn, fullfn, owner, group)

    def _checkDirIsEmpty(self, fn):
        assert self.__validPath(fn)

        bFound = False
        for fn2 in os.listdir(self.__fn2fullfn(fn)):
            if not fn2.startswith(".keep"):
                bFound = True
                break
        if bFound:
            # dangerous to autofix
            self.p._errCb("\"%s\" is not empty." % (fn))

    def _checkNoRedundantFilesWithoutRecursion(self, fn, bIgnoreDotKeepFiles=False):
        assert self.__validPath(fn)

        fullfn = self.__fn2fullfn(fn)
        for fn2 in os.listdir(fullfn):
            if bIgnoreDotKeepFiles and fn2.startswith(".keep"):
                continue
            fullfn2 = os.path.join(fn, fn2)
            if fullfn2 not in self.p._record:
                self.p._errCb("\"%s\" should not exist." % (fullfn2))

    def _batchCheckBasic(self, fn):
        assert self.__validPath(fn)

        fullfn = self.__fn2fullfn(fn)
        s = os.lstat(fullfn)

        # check filename
        if True:
            baseFn = os.path.basename(fullfn)
            if unicodedata.normalize('NFC', baseFn) != baseFn:
                self.p._errCb("\"%s\" has an unnormalized name." % (fn))

        # check owner / group
        if True:
            try:
                pwd.getpwuid(s.st_uid)
            except KeyError:
                self.p._errCb("\"%s\" has an invalid owner." % (fn))
            try:
                grp.getgrgid(s.st_gid)
            except KeyError:
                self.p._errCb("\"%s\" has an invalid group." % (fn))

        # check file mode (basic)
        if True:
            if not (s.st_mode & stat.S_IRUSR):
                self.p._errCb("\"%s\" is not readable by owner." % (fn))
            if not (s.st_mode & stat.S_IWUSR):
                # FIXME: there're so many files violates this rule, strange
                # self.p._errCb("\"%s\" is not writeable by owner." % (fn))
                pass
            if not (s.st_mode & stat.S_IRGRP) and (s.st_mode & stat.S_IWGRP):
                self.p._errCb("\"%s\" is not readable but writable by group." % (fn))
            if not (s.st_mode & stat.S_IROTH) and (s.st_mode & stat.S_IWOTH):
                self.p._errCb("\"%s\" is not readable but writable by other." % (fn))
            if not (s.st_mode & stat.S_IRGRP) and ((s.st_mode & stat.S_IROTH) or (s.st_mode & stat.S_IWOTH)):
                self.p._errCb("\"%s\" is not readable by group but readable/writable by other." % (fn))
            if not (s.st_mode & stat.S_IWGRP) and (s.st_mode & stat.S_IWOTH):
                self.p._errCb("\"%s\" is not writable by group but writable by other." % (fn))

        # check file mode (advanced)
        if True:
            if (s.st_mode & stat.S_ISVTX):
                self.p._errCb("\"%s\" should not have sticky bit set." % (fn))

        # dedicated check for symlink
        if stat.S_ISLNK(s.st_mode):
            if not os.path.exists(fullfn):
                self.p._errCb("\"%s\" is a broken symlink." % (fn))
            if stat.S_IMODE(s.st_mode) != 0o0777:
                self.p._errCb("\"%s\" has invalid permission." % (fn))
            return

        # dedicated check for directory
        if stat.S_ISDIR(s.st_mode):
            if (s.st_mode & stat.S_ISUID):
                self.p._errCb("\"%s\" should not have SUID bit set." % (fn))
            if (s.st_mode & stat.S_ISGID):
                # if showdn.startswith("/var/lib/portage"):
                #     pass        # FIXME, portage set SGID for these directories?
                # elif showdn.startswith("/var/log/portage"):
                #     pass        # FIXME, portage set SGID for these directories?
                # elif showdn.startswith("/var/log/journal"):
                #     pass        # FIXME, systemd set SGID for these directories?
                # else:
                #     self.p._errCb("\"%s\" should not have SGID bit set." % (showdn))
                pass
            return

        # dedicated check for regular file
        if stat.S_ISREG(s.st_mode):
            if (s.st_mode & stat.S_ISUID):
                bad = False
                if not (s.st_mode & stat.S_IXUSR):
                    bad = True
                if not (s.st_mode & stat.S_IXGRP) and ((s.st_mode & stat.S_IRGRP) or (s.st_mode & stat.S_IWGRP)):
                    bad = True
                if not (s.st_mode & stat.S_IXOTH) and ((s.st_mode & stat.S_IROTH) or (s.st_mode & stat.S_IWOTH)):
                    bad = True
                if bad:
                    self.p._errCb("\"%s\" is not appropriate for SUID bit." % (fn))
            if (s.st_mode & stat.S_ISGID):
                # FIXME
                # self.infoPrinter.printError("File \"%s\" should not have SGID bit set." % (showfn))
                pass
            return

        # all other file types are invalid for batch check
        self.p._errCb("Type of \"%s\" is invalid." % (fn))

    def _batchCheckOwnerGroup(self, fn, owner, group):
        assert self.__validPath(fn)
        self.__checkOwnerGroup(fn, self.__fn2fullfn(fn), owner, group)

    def __checkMode(self, fn, fullfn, mode):
        assert not os.path.islink(fullfn)
        assert stat.S_IFMT(mode) == 0                      # no file type bits

        s = os.lstat(fullfn)

        if stat.S_IMODE(s.st_mode) != mode:
            if self.p._bAutoFix:
                os.chmod(fullfn, mode)
            else:
                self.p._errCb("\"%s\" has invalid permission." % (fn))

    def __checkOwnerGroup(self, fn, fullfn, owner, group):
        assert (owner is None and group is None) or (isinstance(owner, int) and isinstance(group, int)) or (isinstance(owner, str) and isinstance(group, str))

        if isinstance(owner, int):
            ownerId = owner
        else:
            ownerId = pwd.getpwnam(owner).pw_uid
        if isinstance(group, int):
            groupId = group
        else:
            groupId = grp.getgrnam(group).gr_gid

        s = os.lstat(fullfn)

        if s.st_uid != ownerId:
            if self.p._bAutoFix:
                os.lchown(fullfn, ownerId, s.st_gid)
            else:
                self.p._errCb("\"%s\" has invalid owner." % (fn))

        if s.st_gid != groupId:
            if self.p._bAutoFix:
                os.lchown(fullfn, s.st_uid, groupId)
            else:
                self.p._errCb("\"%s\" has invalid owner group." % (fn))

    def __fn2fullfn(self, fn):
        return os.path.join(self.p._dirPrefix, fn[1:])

    def __fullfn2fn(self, fullfn):
        t = _pathAddSlash(self.p._dirPrefix)
        return "/" + fullfn[len(t):]

    def __validPath(self, fn):
        if fn == "/":
            return True
        if os.path.isabs(fn) and not fn.endswith("/"):
            return True
        return False


class _HelperUsrMerge:

    @staticmethod
    def compare_dir(src, dst):
        left_list = os.listdir(src)
        right_list = os.listdir(dst)
        ret = []

        for li in left_list:
            if li not in right_list:
                continue

            fli = os.path.join(src, li)
            fri = os.path.join(dst, li)

            r1 = (os.path.islink(fli) and os.path.realpath(fli) == os.path.abspath(fri))
            r2 = (os.path.islink(fri) and os.path.realpath(fri) == os.path.abspath(fli))
            if r1 or r2:
                continue

            if not _isRealDir(fli):
                ret.append((fli, "left-file"))
                continue

            if not _isRealDir(fri):
                ret.append((fli, "right-file"))
                continue

            if not _hasSameStat(fli, fri):
                ret.append((fli, "stat-not-same"))
                continue

            ret += _HelperUsrMerge.compare_dir(fli, fri)

        return ret

    @staticmethod
    def move_dir(src, dst):
        left_list = os.listdir(src)
        right_list = os.listdir(dst)

        for li in left_list:
            fli = os.path.join(src, li)
            fri = os.path.join(dst, li)

            if li not in right_list:
                os.rename(fli, fri)
                continue

            if os.path.islink(fli) and os.path.realpath(fli) == os.path.abspath(fri):
                os.remove(fli)
                continue

            if os.path.islink(fri) and os.path.realpath(fri) == os.path.abspath(fli):
                os.remove(fri)
                os.rename(fli, fri)
                continue

            if _isRealDir(fli) and _isRealDir(fri) and _hasSameStat(fli, fri):
                _HelperUsrMerge.move_dir(fli, fri)
            else:
                raise MoveDirError(fli)

        os.rmdir(src)


def _isToolChainName(name):
    # FIXME: how to find a complete list?
    if name == "i686-pc-linux-gnu":
        return True
    elif name == "x86_64-pc-linux-gnu":
        return True
    elif name == "x86_64-w64-mingw32":
        return True
    else:
        return False


def _pathAddSlash(path):
    if path == "/":
        return path
    else:
        return path + "/"


def _isRealDir(path):
    return os.path.isdir(path) and not os.path.islink(path)


def _hasSameStat(path1, path2):
    st1 = os.stat(path1)
    st2 = os.stat(path2)
    if st1.st_mode != st2.st_mode:
        return False
    if st1.st_uid != st2.st_uid:
        return False
    if st1.st_gid != st2.st_gid:
        return False
    return True


def _makeDeviceNodeFile(path, devType, major, minor, mode, owner, group):
    if devType == "b":
        flag = stat.S_IFBLK
    elif devType == "c":
        flag = stat.S_IFCHR
    else:
        assert False
    os.mknod(path, flag | mode, os.makedev(major, minor))

    ownerId = pwd.getpwnam(owner).pw_uid
    groupId = grp.getgrnam(group).gr_gid
    os.chown(path, ownerId, groupId)


def _doNothing(msg):
    pass
