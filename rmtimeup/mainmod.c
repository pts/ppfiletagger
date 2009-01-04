/* 
 * mainmod.c -- main source file for the rmtimeup Linux kernel module
 * kernel module for 2.6.x kernels (tested with 2.6.18.1 and 2.6.22.1)
 * by pts@fazekas.hu at Sat Jan  3 15:41:02 CET 2009
 *
 * rmtimeup is a Linux i386 (x86) 32-bit kernel module which updates the
 * mtime of all ancestor directories for all interesting file operations:
 * rename, unlink, link, setxattr on files. To do this, it hooks some kernel
 * functions (e.g. vfs_rename, vfs_link). rmtimeup can be used
 * as a component of a local filesystem indexing framework (similar to Beagle,
 * rlocate and movemetafs). See rmtimeup.txt for more details.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/* !! do we need spin_lock_irq/spin_lock_irqsave? a simple spin_lock would be enough */
/* !! get rid of compile warnings */
/* !! use shared (for documentation purposes) */
/* TODO: use mtime/atime/ctime of fs root inode to detect that it has been
 *       mounted without this kernel module. atime detects ls /fsroot, but not
 *       any operatin on /fsroot/foo/bar.
 *       * propose a solution which survives an unclean umount
 *       * ext2 has mount count, last mount time, last write time (tune2fs),
 *         reiserfs doesn't have these features
 * TODO: sometimes an `mv' makes the system freeze
 */

#include <linux/kernel.h>
#include <linux/version.h>
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/moduleparam.h>

#include <linux/init.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/namei.h>

#include "ud.h"

MODULE_AUTHOR("Peter Szabo");
MODULE_DESCRIPTION("rmtimeup "RMTIMEUP_VERSION" recursive filesystem change notify");
MODULE_LICENSE("GPL");

#define COMPILING 1
#ifdef CONFIG_SECURITY
#else
#  error please enable CONFIG_SECURITY
#  undef COMPILING
#endif

#ifdef COMPILING

/**** pts ****/
#undef  SUPPORT_UPDATEDB_ARG
#define SUPPORT_UPDATEDB_ARG 0
#undef  SUPPORT_OUTPUT_ARG
#define SUPPORT_OUTPUT_ARG 0
#undef  SUPPORT_EXCLUDEDIR
/** Just a setting, not used by the kernel module. */
#define SUPPORT_EXCLUDEDIR 0

#ifndef SETPROC_OPS
#define SETPROC_OPS(entry, ops) (entry)->proc_fops = &(ops)
#endif

/** File name of the tags database in the filesystem root */
#define TAGDB_NAME "tags.sqlite"

#define MOD_REG_NAME "rmtimeup"

/* !! properly fail */
#define assert(x) do { if (!(x)) { printk(KERN_ERR "assertion failed: %s\n", #x); } } while(0)

/* !! implement this */
int debug;
module_param_named(debug, debug, int, 0);
MODULE_PARM_DESC(debug, "print KERN_DEBUG messages");

/* --- */

/*
 * get_path() return the path of a dentry with major and minor number instead
 * of mount point.
 */
inline static char *get_path(struct dentry *dentry, char *buffer, int buflen) {
  char * end = buffer + buflen;
  int namelen;
  /* why don't we use built-in d_path()? */
  /* TODO: do we have all locks (such as for d_path?) */
  /* TODO: do we need a dget/dput here? or current->fs->lock? */ 

  *--end = '\0';
  buflen--;

  end[-1]='/'; /**** pts ****/
  for (;;) {
    struct dentry *parent;
    if (IS_ROOT(dentry)) goto mountroot;
    parent = dentry->d_parent;
    prefetch(parent);
    namelen = dentry->d_name.len;
    buflen -= namelen + 1;
    if (buflen < 0)
            goto Elong;
    end -= namelen;
    memcpy(end, dentry->d_name.name, namelen);
    *--end = '/';
    dentry = parent;
  }
 mountroot:
  namelen = strlen(dentry->d_sb->s_id);
  buflen -=namelen + 2;
  if (buflen < 0)
          goto Elong;
  *--end = ':';
  end -= namelen;
  memcpy(end, dentry->d_sb->s_id, namelen);
  return end;
 Elong:
  return ERR_PTR(-ENAMETOOLONG);
}

/* !! hook setxattr */

/** Find the dentry of file with TAGDB_NAME on the filesystem sb.
 * The caller should dput the returned value unless IS_ERR(retval).
 */
static struct dentry *get_dentry_tagdb(struct super_block *sb,
    struct dentry *nolock1, struct dentry *nolock2) {
  struct dentry *root = dget(sb->s_root);
  struct dentry *tagdb;
  char do_lock = root != nolock1 && root != nolock2;
  if (do_lock) mutex_lock(&root->d_inode->i_mutex);
  tagdb = lookup_one_len(TAGDB_NAME, root, strlen(TAGDB_NAME));
  if (do_lock) mutex_unlock(&root->d_inode->i_mutex);
  dput(root);
  if (!IS_ERR(tagdb) && tagdb->d_inode == NULL) {
    dput(tagdb);
    tagdb = ERR_PTR(-ENOENT);
  }
  return tagdb;
}

/** Return true iff filesystem sb has TAGDB_NAME in its root directory */
static __always_inline char has_dentry_tagdb(struct super_block *sb,
    struct dentry *nolock1, struct dentry *nolock2) {
  struct dentry *tagdb = get_dentry_tagdb(sb, nolock1, nolock2);
  if (IS_ERR(tagdb)) return 0;
  /* example: (long)dentry_tagdb->d_inode->i_mtime.tv_sec); */
  dput(tagdb);
  return 1;
}

/** Start in root, traverse directories path ("DEV:/DIR1/DIR2/FILENAME"),
 * return the dentry reached (i.e. dentry of DIR2).
 * If there is an error traversing, return dentry reached without errors.
 *
 * The caller should call dput(retval) and dget(root).
 */
struct dentry *dentry_from_path(struct dentry *root, char const *path,
    struct dentry *nolock1, struct dentry *nolock2) {
  struct dentry *dentry1, *dentry2;
  char do_lock;
  char const *p = path;
  char const *q;
  while (*p != '\0' && *p != '/') ++p;  /* skip "sda1:" */
  dentry1 = dget(root);
  while (1) {
    while (*p == '/') ++p;
    if (*p == '\0') break;
    q = p;
    while (*q != '\0' && *q != '/') ++q;
    /* %*s in printk doesn't truncate the string (q - p) */
    printk(KERN_INFO "in dentry1=%p lookup=(%*s)\n", dentry1, q - p, p);
    do_lock = dentry1 != nolock1 && dentry1 != nolock2;
    if (do_lock) mutex_lock(&dentry1->d_inode->i_mutex);
    dentry2 = lookup_one_len(p, dentry1, q - p);  /* does dget(dentry2) */
    if (do_lock) mutex_unlock(&dentry1->d_inode->i_mutex);
    if (!IS_ERR(dentry2) && dentry2->d_inode == NULL) {
      dput(dentry2);
      dentry2 = ERR_PTR(-ENOENT);
    }
    if (IS_ERR(dentry2)) break;
    if (!S_ISDIR(dentry2->d_inode->i_mode)) { dput(dentry2); break; }
    dput(dentry1);
    dentry1 = dentry2;
    p = q;
  }
  printk(KERN_INFO "traversed to dentry1=%p\n", dentry1);
  return dentry1;
}

/** Updates mtime of dentry, dentry->parent etc., up to dentry->d_sb->s_root. */
/*!!static*/ void update_mtimes_and_dput(struct dentry *dentry,
    struct timespec now,
    struct dentry *nolock1, struct dentry *nolock2) {
  struct dentry *dentry_set = dentry;
  struct iattr newattrs;
  struct inode *inode;
  char do_lock;
  int error;

  printk(KERN_INFO "update_mtime dentry=%p now=%ld\n",
      dentry, (long)now.tv_sec);
  newattrs.ia_valid = ATTR_MTIME;
  newattrs.ia_mtime = now;
  while (1) {
    inode = dentry_set->d_inode;
    /* IS_RDONLY(inode) is true for a read-only filesystem */
    if (!IS_RDONLY(inode) && !IS_IMMUTABLE(inode) && !IS_APPEND(inode)) {
      do_lock = dentry_set != nolock1 && dentry_set != nolock2;
      if (do_lock) mutex_lock(&inode->i_mutex);
      error = inode_setattr(inode, &newattrs);   /* bypasses permission checks */
      if (error) printk(KERN_WARNING "update_mtime error i_ino=%ld error=%d\n",
          (long)inode->i_ino, error);
      if (do_lock) mutex_unlock(&inode->i_mutex);
    }
    if (IS_ROOT(dentry_set)) break;
    dentry_set = dentry_set->d_parent;
  }
  dput(dentry);
};

#if 0
static int wrapped_callback(
    int origret, void *ptr0, void *ptr1, void *ptr2, void *ptr3, void *ptr4) {
  char *old_path = ptr0, *new_path = ptr2;
  struct dentry *old_dentry = ptr1, *new_dentry = ptr3, *root = ptr4;
  struct timespec now = current_fs_time(new_dentry->d_sb);
  printk(KERN_INFO "rmtimeup: origret=%d oldcont=(%s) newcont=(%s)\n",
      origret, old_path, new_path);
  if (origret == 0) {
    /* We specify nolock1=old_dentry->d_parent and nolock2=new_dentry->d_parent
     * because
     * lock_rename in fs/namei.c has already locked those inodes, and if we
     * tried to lock again, we would get a deadlock.
     */
    update_mtimes_and_dput(dentry_from_path(root, old_path,
        /*nolock1:*/old_dentry->d_parent, /*nolock2:*/new_dentry->d_parent),
        now,
        /*nolock1:*/old_dentry->d_parent, /*nolock2:*/new_dentry->d_parent);
    update_mtimes_and_dput(dentry_from_path(root, new_path,
        /*nolock1:*/old_dentry->d_parent, /*nolock2:*/new_dentry->d_parent),
        now,
        /*nolock1:*/old_dentry->d_parent, /*nolock2:*/new_dentry->d_parent);
  }
  dput(root);
  kfree(old_path);
  kfree(new_path);
  /* return -ENOTCONN; // too late to return an error, the move has already taken place */
  return origret;
}

RETURN_WRAP(static, int, rmtimeup_inode_rename,
    struct inode * old_dir,
    struct dentry * old_dentry,
    struct inode * new_dir,
    struct dentry * new_dentry ) {
  char path_buffer[PATH_MAX + 16], *old_path, *new_path;
  printk(KERN_INFO "rename ebp=%p esp0=%p eip=%p "
      "a=%p b=%p c=%p d=%p\n",
      wrap__ebp, wrap__esp0, wrap__eip,
      old_dir, old_dentry, new_dir, new_dentry);
  if (new_dentry->d_inode) return 0;
  /* ^^^ Dat: usually we get an `aX' for new_dentry, inode is not
   *     available yet (for CONFIG_SECURITY handlers)
   */
  assert(old_dentry->d_sb == new_dentry->d_sb);  /* on same filesystem */
  if (!has_dentry_tagdb(new_dentry->d_sb,
      /*nolock1:*/old_dentry->d_parent,
      /*nolock2:*/new_dentry->d_parent)) return 0;
  old_path = kstrdup(get_path(old_dentry, path_buffer, sizeof path_buffer),
      GFP_KERNEL);
  new_path = kstrdup(get_path(new_dentry, path_buffer, sizeof path_buffer),
      GFP_KERNEL);
  /* !! disallow module onload while call pending */
  printk(KERN_INFO "rmtimeup: old=(%s) new=(%s)\n", old_path, new_path);
  RETURN_WITH_CALLBACK_REGISTER(
      /*ptr0:*/old_path, /*ptr1:*/old_dentry,
      /*ptr2:*/new_path, /*ptr3:*/new_dentry,
      /*ptr4:*/dget(new_dentry->d_sb->s_root),
      /*fakecallback:*/wrapped_callback);
}
#endif

#if 0
void rmtimeup_inode_post_setxattr(struct dentry *dentry, char *name,
    void *value, size_t size, int flags) {
  /* !! implement this */
  return;  /* the xattr is set anyway */
}

int rmtimeup_inode_removexattr(struct dentry *dentry, char *name) {
  /* !! implement this */
  return 0;
}

static int rmtimeup_sb_mount(char *dev_name, 
			     struct nameidata *nd, 
			     char *type, 
			     unsigned long flags, 
			     void *data) {
  /* !! implement this */
  return 0;
}

static int rmtimeup_sb_umount( struct vfsmount *mnt, int flags ) {
  /* !! implement this */
  return 0;
}
#endif

/* --- */

/** Returns a negative integer on error, or a positive integer at least min,
 * containing complete assembly instructions from pc.
 */
int disasm_safe_size(char *pc, int min) {
  unsigned maxbytes = 100;
  char *dins;
  char *dinsend;
  unsigned inslen;
  int inslen_total = 0;
  ud_t ud_obj;
  ud_init(&ud_obj);
  ud_set_mode(&ud_obj, 32);
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);
  ud_set_input_buffer(&ud_obj, (void*)pc, maxbytes);
  ud_set_pc(&ud_obj, (unsigned long)(void*)pc);
  if (debug) printk(KERN_DEBUG "disasm_safe_size pc=%p min=%d\n", pc, min);
  while (inslen_total < min && 0 != (inslen = ud_disassemble(&ud_obj))) {
    inslen_total += inslen;
    dins = ud_insn_asm(&ud_obj);
    dinsend = dins + strlen(dins);
    if (dinsend != dins && dinsend[-1] == ' ') --dinsend;
    *dinsend = '\0'; /* remove trailing space from "ret " etc. */
    if (debug) printk(KERN_DEBUG "D%08lx  %s;\n", (unsigned long)ud_insn_off(&ud_obj), dins);
    if (0 == strncmp(dins, "push ", 5)) {
    } else if (0 == strncmp(dins, "jmp 0x", 6)) {
      /* !! not always */
    } else if ((0 == strncmp(dins, "mov ", 4) ||
                0 == strncmp(dins, "sub ", 4) ||
                0 == strncmp(dins, "add ", 4)) &&
               0 != strncmp(dins + 4, "[esp", 4)) {
    } else {
      printk(KERN_INFO "unsafe assembly instruction\n");
      return -EILSEQ;
    }
  }
  return inslen_total >= min ? inslen_total : -EMSGSIZE;
} 

/* --- */

#define JMP_SIZE 5
#define MAX_TRAMPOLINE_SIZE 24

/* Set 5 bytes starting from p to a `jmp dword jmp_target' i386 instruction. */
static __always_inline void set_jmp32(char *p, char *jmp_target) {
  /* This assumes i386 32-bit architecture */
  int32_t relative = (int32_t)(jmp_target - p - JMP_SIZE);
  register int32_t first = 0xE9 | (relative << 8);
  /* Imp: is there a better specifier than volatile? */
  /* We set p[4] first, because if another processor is alredy running the
   * code, p[4] is expected to be already fetched.
   */
  ((volatile char*)p)[4] = relative >> 24;
  *(volatile int32_t*)p = first;
}

/** If there is a `jmp dword jmp_target' i386 instruction at p, return
 * jmp_target, otherwise return NULL;
 */
char *get_jmp32_target(char *p) {
  if (p[0] != (char)0xE9) return NULL;
  return *(int32_t*)(p + 1) + p + JMP_SIZE;
}

struct hook {
  char trampoline[MAX_TRAMPOLINE_SIZE];
  char jmp_to_replacement[JMP_SIZE];
  /* char* wouldn't work after rmmod(1) */
  char name[32];
  /** The hook is void iff orig_function == NULL. */
  char *orig_function;
  char *replacement_function;
};

/** Return 0 if undone properly, 1 if some indirections still remain (but
 * references to hook->replacement_function are removed.
 */
static int undo_hook(struct hook *hook) {
  register char *p, *q;
  if (hook->orig_function != NULL) {
    printk(KERN_DEBUG "undoing hook %s.\n", hook->name);
    if (get_jmp32_target(hook->orig_function) == hook->jmp_to_replacement) {
      p = hook->orig_function;
      q = hook->trampoline;
      /* overwrite this first, already in the instruction cache if executing
       * on another processor
       */
      p[4] = q[4];
      *(int32_t*)p = *(int32_t*)q;
      hook->orig_function = NULL;
    } else {
      printk(KERN_WARNING "rmtimeup: could not unhook %s.\n", hook->name);
      set_jmp32(hook->jmp_to_replacement, hook->trampoline);
      hook->replacement_function = NULL;
      return 1;
    }
    hook->replacement_function = NULL;
  }
  return 0;
}

/** Set fields of hook, modify code pointers. Return 0 or error. */
static int set_hook(char *orig_function, char *replacement_function,
    char *name, struct hook *hook, char **prev_out) {
  int safe_size_orig = disasm_safe_size(orig_function, JMP_SIZE);
  if (safe_size_orig < 0) return safe_size_orig;  /* error */
  strncpy(hook->name, name, sizeof(hook->name));
  hook->name[sizeof(hook->name) - 1] = '\0';
  hook->orig_function = orig_function;
  hook->replacement_function = replacement_function;
  /* This indirection is needed for undoing hooks. */
  set_jmp32(hook->jmp_to_replacement, replacement_function);
  memcpy(hook->trampoline, orig_function, safe_size_orig);
  set_jmp32(hook->trampoline + safe_size_orig,
      orig_function + safe_size_orig);
  set_jmp32(orig_function, hook->jmp_to_replacement);  /* do this last */
  if (prev_out != NULL) *prev_out = hook->trampoline;
  return 0;
}

/** Good gcc type checking if function_name doesn't have __VA_ARGS__:
 * warning: initialization from incompatible pointer type
 */
#define DEFINE_ANCHOR(function_name, ...) \
  static int function_name##__repl(__VA_ARGS__); \
  static struct { \
    /* Call this within DEFINE_ANCHOR(foo):
     * foo__anchor.prev(...)
     */ \
    int (*prev)(__VA_ARGS__); \
    int (*orig_function)(__VA_ARGS__); \
    int (*replacement_function)(__VA_ARGS__); \
    char *name; \
  } function_name##__anchor = { \
    .prev = NULL, \
    .orig_function = function_name,  /* warn on type error */ \
    .replacement_function = function_name##__repl, \
    .name = #function_name, \
  }; \
  static int function_name##__repl(__VA_ARGS__)

#define SETUP_HOOK(function_name, i) \
  set_hook( \
      /*orig_function:*/(char*)function_name##__anchor.orig_function, \
      /*replacement_function:*/(char*)function_name##__anchor.replacement_function, \
      /*name:*/function_name##__anchor.name, \
      /*hook:*/rmtimeup_hooks + (i), \
      /*prev_out:*/(char**)&function_name##__anchor.prev)

/* --- */

DEFINE_ANCHOR(vfs_rename,
              struct inode *old_dir, struct dentry *old_dentry,
              struct inode *new_dir, struct dentry *new_dentry) {
  int prevret;
  printk(KERN_INFO "my vfs_rename called\n");
  prevret = vfs_rename__anchor.prev(
      old_dir, old_dentry, new_dir, new_dentry);
  printk(KERN_INFO "my vfs_rename prevret=%d\n", prevret);
  return prevret;  
}

DEFINE_ANCHOR(vfs_link,
              struct dentry *old_dentry, struct inode *dir,
              struct dentry *new_dentry) {
  int prevret;
  printk(KERN_INFO "my vfs_link called\n");
  prevret = vfs_link__anchor.prev(
      old_dentry, dir, new_dentry);
  printk(KERN_INFO "my vfs_link prevret=%d\n", prevret);
  return prevret;  
}

DEFINE_ANCHOR(vfs_unlink,
              struct inode *dir, struct dentry *dentry) {
  int prevret;
  printk(KERN_INFO "my vfs_unlink called\n");
  prevret = vfs_unlink__anchor.prev(dir, dentry);
  printk(KERN_INFO "my vfs_unlink prevret=%d\n", prevret);
  return prevret;
}

/* --- */

#define MAX_RMTIMEUP_HOOKS 8
spinlock_t hooks_lock;
static struct hook *rmtimeup_hooks = NULL;

static char undo_all_hooks(void) {
  int i;
  char do_keep = 0;
  for (i = 0; i < MAX_RMTIMEUP_HOOKS; ++i) {
    if (undo_hook(rmtimeup_hooks + i)) do_keep = 1;
  }
  return do_keep;
}

static int init_hooks(void) {
  unsigned long irq_flags;
  int error;
  spin_lock_init(&hooks_lock);
  if (NULL == (rmtimeup_hooks = kmalloc(
      MAX_RMTIMEUP_HOOKS * sizeof*rmtimeup_hooks, GFP_KERNEL))) {
    error = -ENOMEM;
    goto do_exit;
  }
  memset(rmtimeup_hooks, '\0', MAX_RMTIMEUP_HOOKS * sizeof*rmtimeup_hooks);
  spin_lock_irqsave(&hooks_lock, irq_flags);  /* Imp: smaller lock */
  /* If you add hooks, don't forget to increase MAX_RMTIMEUP_HOOKS */
  if (0 != (error = SETUP_HOOK(vfs_rename, 0)) ||
      0 != (error = SETUP_HOOK(vfs_unlink, 1)) ||
      0 != (error = SETUP_HOOK(vfs_link, 2))) {
    undo_all_hooks();
    goto do_unlock;
  }
  error = 0;
 do_unlock:
  spin_unlock_irqrestore(&hooks_lock, irq_flags);
 do_exit:
  return error;
}

static void exit_hooks(void) {
  char do_keep;
  unsigned long irq_flags;
  /* TODO: add mutex in case of removing the module while a vfs_rename is
   * in progress. Is this possible?
   */
  spin_lock_irqsave(&hooks_lock, irq_flags);  /* Imp: smaller lock */
  do_keep = undo_all_hooks();
  spin_unlock_irqrestore(&hooks_lock, irq_flags);
  if (do_keep) {
    /* Keep rmtimeup_hooks if we couldn't unhook everything. */
    printk(KERN_WARNING "rmtimeup: %d bytes leaked when unloading\n",
        sizeof*rmtimeup_hooks);
  } else {
    kfree(rmtimeup_hooks);
  }
}

static int __init init_rmtimeup(void) {
  int ret;
  printk(KERN_INFO "rmtimeup version "RMTIMEUP_VERSION" loaded\n");
  if (debug) printk(KERN_DEBUG "rmtimeup hello version "RMTIMEUP_VERSION" loaded\n");
  
  ret = init_hooks();
  if (ret) goto done;
  ret = 0;
 done:
  return ret;
}

/*
 * exit_rmtimeup()
 */
static void __exit exit_rmtimeup(void) {
  exit_hooks();
  printk(KERN_INFO "rmtimeup: unloaded\n");
}

module_init(init_rmtimeup);
module_exit(exit_rmtimeup);

#endif /* COMPILING */
