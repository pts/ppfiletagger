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
#include <linux/sched.h>  /* TASK_INTERRUPTIBLE */
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/moduleparam.h>

#include <linux/init.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/namei.h>
#include <linux/kallsyms.h>
#include <linux/mount.h>

#include <asm/pgtable.h>  // PAGE_KERNEL_EXEC
#include <linux/vmalloc.h>

MODULE_AUTHOR("Peter Szabo");
MODULE_DESCRIPTION("rmtimeup "RMTIMEUP_VERSION" recursive filesystem change notify");
MODULE_LICENSE("GPL");

#ifndef USE_EXTERN_PAGE_KERNEL_EXEC
#  define USE_EXTERN_PAGE_KERNEL_EXEC 0
#endif

#ifndef USE_EXTRA_VFSMNT
#  define USE_EXTRA_VFSMNT 0
#endif
#if USE_EXTRA_VFSMNT
#  define VFSMNT_TARG(name) , struct vfsmount *name
#  define VFSMNT_ARG(name) , name
#  define FILE_TARG(name) , struct file *name
#else
#  define VFSMNT_TARG(name)
#  define VFSMNT_ARG(name)
#  define FILE_TARG(name)
#endif

#ifndef USE_SPRINT_SYMBOL
#  define USE_SPRINT_SYMBOL 0
#endif

#ifndef USE_VFS_CONST_ARG
#  define USE_VFS_CONST_ARG 0
#endif
#if USE_VFS_CONST_ARG
typedef const char *vfs_name_t;
typedef const void *vfs_value_t;
#else
typedef char *vfs_name_t;
typedef void *vfs_value_t;
#endif

#ifndef USE_MODULE_OWNER
#  define USE_MODULE_OWNER 0
#endif

#ifndef SETPROC_OPS
#define SETPROC_OPS(entry, ops) (entry)->proc_fops = &(ops)
#endif

/** File name of the tags database in the filesystem root */
#define TAGDB_NAME "tags.sqlite"

/* TODO: fail properly */
#define assert(x) do { if (!(x)) printk(KERN_ERR \
    "%s: assertion failed: %s\n", THIS_MODULE->name, #x); } while(0)

int debug;
module_param_named(debug, debug, int, 0);
MODULE_PARM_DESC(debug, "print KERN_DEBUG messages");

/* Usage: PRINT_DEBUG("hello\n%s", ""); */
#define PRINT_DEBUG(fmt_string, ...) do { if (debug) printk(KERN_DEBUG \
    "%s: " fmt_string, THIS_MODULE->name, __VA_ARGS__); } while(0)

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
  buflen -= namelen + 2;
  if (buflen < 0)
          goto Elong;
  *--end = ':';
  end -= namelen;
  memcpy(end, dentry->d_sb->s_id, namelen);
  return end;
 Elong:
  return ERR_PTR(-ENAMETOOLONG);
}

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

/** Updates mtime of dentry, dentry->parent etc., up to dentry->d_sb->s_root.
 * The caller should make sure that has_dentry_tagdb(d->d_sb, nolock1, nolock2)
 * returns true.
 */
static void update_mtimes(struct dentry *dentry,
    struct timespec now,
    struct dentry *nolock1, struct dentry *nolock2) {
  struct dentry *dentry_set = dentry;
  struct iattr newattrs;
  struct inode *inode;
  char do_lock;
  int error;

  PRINT_DEBUG("update_mtime dentry=%p now=%ld\n",
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
};

/* --- /proc/rmtimeup-event */

/** Constants for rmtimeup_event.value */
#define EVENT_FILES_CHANGED '1'
#define EVENT_MOUNTS_CHANGED '2'
/* #define EVENT_FILES_AND_MOUNTS_CHANGED '3' */

struct rmtimeup_event {
  struct list_head list;
  /** Entities waiting for read. */
  wait_queue_head_t wq;
  /** Held when getting or setting .value. */
  rwlock_t value_lock;
  /** 0: no data; '1': some files changed; '2': mounts changed; '3': '1'|'2' */
  char value;
};

/** Held when reading or writing rmtimeup_event_list. */
static DEFINE_SPINLOCK(rmtimeup_event_list_lock);
static LIST_HEAD(rmtimeup_event_list);

/** May return ERR_PTR(...) */
static struct rmtimeup_event *new_rmtimeup_event(void) {
  unsigned long irq_flags;
  struct rmtimeup_event *ev = kmalloc(sizeof*ev, GFP_KERNEL);
  if (NULL == ev) return ERR_PTR(-ENOMEM);
  rwlock_init(&ev->value_lock);
  ev->value = 0;
  INIT_LIST_HEAD(&ev->list);
  init_waitqueue_head(&ev->wq);
  spin_lock_irqsave(&rmtimeup_event_list_lock, irq_flags);
  list_add(&ev->list, &rmtimeup_event_list);
  spin_unlock_irqrestore(&rmtimeup_event_list_lock, irq_flags);
  return ev;
}

static void delete_rmtimeup_event(struct rmtimeup_event *ev) {
  assert(ev != NULL);
  if (ev != NULL) {
    unsigned long irq_flags;
    spin_lock_irqsave(&rmtimeup_event_list_lock, irq_flags);
    list_del(&ev->list);
    spin_unlock_irqrestore(&rmtimeup_event_list_lock, irq_flags);
    kfree(ev);
  }
}

void notify_rmtimeup_events(char value) {
  unsigned long irq_flags;
  struct list_head *pos;
  struct rmtimeup_event *ev;
  char old_value;
  value = '0' + (value & 3);
  if (0 == value) return;
  /* Imp: hold the spin lock for less time */
  spin_lock_irqsave(&rmtimeup_event_list_lock, irq_flags);
  list_for_each(pos, &rmtimeup_event_list) {
    ev = (struct rmtimeup_event*)pos;  /* list_entry(pos, struct rmtimeup_event, list) */
    write_lock(&ev->value_lock);  /* irq_flags saved above */
    old_value = ev->value;
    ev->value |= value;
    write_unlock(&ev->value_lock);
    if (old_value != value) wake_up_interruptible(&ev->wq);
  }
  spin_unlock_irqrestore(&rmtimeup_event_list_lock, irq_flags);
}

static int rmtimeup_event_open(struct inode *inode, struct file *filp) {
  struct rmtimeup_event *ev;
  if (0 != (filp->f_mode & FMODE_WRITE)) return -EACCES;  /* even for root */
  ev = new_rmtimeup_event();
  if (IS_ERR(ev)) return PTR_ERR(ev);
  filp->private_data = (void*)ev;
  return 0;
}

static int rmtimeup_event_release(struct inode *inode, struct file *filp) {
  delete_rmtimeup_event((struct rmtimeup_event*)filp->private_data);
  return 0;
}

static ssize_t rmtimeup_event_read(
    struct file *filp, char *user_buffer, size_t len, loff_t *offset) {
  struct rmtimeup_event *ev = (struct rmtimeup_event*)filp->private_data;
  char value;
  unsigned long irq_flags;
  DEFINE_WAIT(wait);
  while (1) {
    write_lock_irqsave(&ev->value_lock, irq_flags);
    value = ev->value;
    if (value != 0) break;
    write_unlock_irqrestore(&ev->value_lock, irq_flags);

    /* Imp: do we wait correctly? */
    prepare_to_wait(&ev->wq, &wait, TASK_INTERRUPTIBLE);
    schedule();
    finish_wait(&ev->wq, &wait);
    if (signal_pending(current)) return -ERESTARTSYS;
  }
  ev->value = 0;
  write_unlock_irqrestore(&ev->value_lock, irq_flags);
  if (put_user(value, user_buffer)) return -EFAULT;
  ++*offset;
  return 1;
}

static unsigned rmtimeup_event_poll(struct file *filp, poll_table *wait) {
  struct rmtimeup_event *ev = (struct rmtimeup_event*)filp->private_data;
  unsigned mask = 0;
  unsigned long irq_flags;
  poll_wait(filp, &ev->wq, wait);
  read_lock_irqsave(&ev->value_lock, irq_flags);
  if (0 != ev->value) mask |= POLLIN | POLLRDNORM;
  read_unlock_irqrestore(&ev->value_lock, irq_flags);
  return mask;
}

static ssize_t rmtimeup_event_write(struct file *filp,
                                    const char *user_buffer,
                                    size_t len,
                                    loff_t *offset) {
  return -EINVAL;
}

static loff_t rmtimeup_event_llseek(struct file *filp, loff_t ofs,
    int whence) {
  return -ESPIPE;
}

static struct file_operations rmtimeup_event_ops = {
  .open    = rmtimeup_event_open,
  .release = rmtimeup_event_release,  /* close */
  .read    = rmtimeup_event_read,
  .write   = rmtimeup_event_write,
  .poll    = rmtimeup_event_poll,
  .llseek  = rmtimeup_event_llseek,
};

/* --- Hooks and anchors */

/* This is i386 (32-bit) specific. */

static struct instruction {
  unsigned char byte0, mask0;
  unsigned char byte1, mask1;
  unsigned char byte2, mask2;
  unsigned short size;
} instructions[] = {
  { .byte0=0x05, .mask0=0xFF                          , .size=5},  /* add eax, dword ... */
  { .byte0=0x0D, .mask0=0xFF                          , .size=5},  /* or  eax, dword ... */
  { .byte0=0x15, .mask0=0xFF                          , .size=5},  /* adc eax, dword ... */
  { .byte0=0x1D, .mask0=0xFF                          , .size=5},  /* sbb eax, dword ... */
  { .byte0=0x25, .mask0=0xFF                          , .size=5},  /* and eax, dword ... */
  { .byte0=0x2D, .mask0=0xFF                          , .size=5},  /* sub eax, dword ... */
  { .byte0=0x29, .mask0=0xFF, .byte1=0xC0, .mask1=0xC0, .size=2},  /* sub r32, r32 */
  { .byte0=0x31, .mask0=0xFF, .byte1=0xC0, .mask1=0xC0, .size=2},  /* xor r32, r32 */
  { .byte0=0x35, .mask0=0xFF                          , .size=5},  /* xor eax, dword ... */
  { .byte0=0x50, .mask0=0xF8                          , .size=1},  /* push r32 */
  { .byte0=0x58, .mask0=0xF8                          , .size=1},  /* pop r32 */
  { .byte0=0x66, .mask0=0xFF, .byte1=0x68, .mask1=0xFF, .size=4},  /* push word ... */
  { .byte0=0x68, .mask0=0xFF                          , .size=5},  /* push dword ... */
  { .byte0=0x6A, .mask0=0xFF                          , .size=2},  /* push byte ... */
  { .byte0=0x81, .mask0=0xFF, .byte1=0xC0, .mask1=0xF8, .size=6},  /* add r32, dword ... */
  { .byte0=0x81, .mask0=0xFF, .byte1=0xC8, .mask1=0xF8, .size=6},  /* or  r32, dword ... */
  { .byte0=0x81, .mask0=0xFF, .byte1=0xD0, .mask1=0xF8, .size=6},  /* adc r32, dword ... */
  { .byte0=0x81, .mask0=0xFF, .byte1=0xD9, .mask1=0xF8, .size=6},  /* sbb r32, dword ... */
  { .byte0=0x81, .mask0=0xFF, .byte1=0xE0, .mask1=0xF8, .size=6},  /* and r32, dword ... */
  { .byte0=0x81, .mask0=0xFF, .byte1=0xE8, .mask1=0xF8, .size=6},  /* sub r32, dword ... */
  { .byte0=0x81, .mask0=0xFF, .byte1=0xF0, .mask1=0xF8, .size=6},  /* xor r32, dword ... */
  { .byte0=0x83, .mask0=0xFF, .byte1=0xC0, .mask1=0xF8, .size=3},  /* add r32, byte ... */
  { .byte0=0x83, .mask0=0xFF, .byte1=0xC8, .mask1=0xF8, .size=3},  /* or  r32, byte ... */
  { .byte0=0x83, .mask0=0xFF, .byte1=0xD0, .mask1=0xF8, .size=3},  /* adc r32, byte ... */
  { .byte0=0x83, .mask0=0xFF, .byte1=0xD9, .mask1=0xF8, .size=3},  /* sbb r32, byte ... */
  { .byte0=0x83, .mask0=0xFF, .byte1=0xE0, .mask1=0xF8, .size=3},  /* and r32, byte ... */
  { .byte0=0x83, .mask0=0xFF, .byte1=0xE8, .mask1=0xF8, .size=3},  /* sub r32, byte ... */
  { .byte0=0x83, .mask0=0xFF, .byte1=0xF0, .mask1=0xF8, .size=3},  /* xor r32, byte ... */
  { .byte0=0x89, .mask0=0xFF, .byte1=0x44, .mask1=0xC7, .byte2=0x24, .mask2=0xFF, .size=4},  /* mov [esp+byte ...], r32 */
  { .byte0=0x89, .mask0=0xFF, .byte1=0xC0, .mask1=0xC0, .size=2},  /* mov r32, r32 */
  { .byte0=0x8B, .mask0=0xFF, .byte1=0x44, .mask1=0xC7, .byte2=0x24, .mask2=0xFF, .size=4},  /* mov r32, [esp+byte ...] */
  { .byte0=0x90, .mask0=0xF8                          , .size=5},  /* xchg eax, r32  (and nop) */
  { .byte0=0xB8, .mask0=0xF8                          , .size=5},  /* mov r32, dword ... */
  { .byte0=0xC3, .mask0=0xFF                          , .size=1},  /* ret */
  { .byte0=0xE8, .mask0=0xFF                          , .size=5},  /* call ... */
  { .byte0=0xE9, .mask0=0xFF                          , .size=5},  /* jmp ... */
  { .byte0=0xEB, .mask0=0xFF                          , .size=2},  /* jmp short ... */
  {},
};

/** Returns a negative integer on error, or a positive integer at least min,
 * containing complete assembly instructions from pc.
 */
int disasm_safe_size(char *pc, int min) {
  int c = 0;
  unsigned char *pcu = pc;
  struct instruction *ins;
  /*return -EILSEQ;*/  /* Invalid or incomplete multibyte or wide character */
  while (c < min) {
    PRINT_DEBUG("c=%d min=%d pcu=%p: 0x%02X 0x%02X 0x%02X\n",
        c, min, pcu, pcu[0], pcu[1], pcu[2]);
    for (ins = instructions; ins->mask0 != 0; ++ins) {
      if (ins->byte0 == (ins->mask0 & pcu[0]) &&
          ins->byte1 == (ins->mask1 & pcu[1]) &&
          ins->byte2 == (ins->mask2 & pcu[2])) goto found;
    }
    printk(KERN_INFO "unrecognized instruction at %p: 0x%2X 0x%2X\n",
        pcu, pcu[0], pcu[1]);
    return -EILSEQ; /*return -EMSGSIZE;*/
   found:
    c += ins->size;
    if (pcu[0] == 0xE8 || pcu[0] == 0xE9 || pcu[0] == 0xEB) { /* jmp or call */
      if (c < min) { pcu = NULL; c = min; }
    }
    pcu += ins->size;
  }
  return c;
}

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
    PRINT_DEBUG("undoing hook %s.\n", hook->name);
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
      printk(KERN_WARNING "%s: could not unhook %s.\n",
          THIS_MODULE->name, hook->name);
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
  int safe_size_orig;
  if (NULL == orig_function) {
    printk(KERN_ERR "%s: orig_function is NULL for %s.\n",
        THIS_MODULE->name, name);
    return -ENOKEY;
  }
  if (0 > (safe_size_orig = disasm_safe_size(orig_function, JMP_SIZE))) {
    printk(KERN_ERR "%s: could not hook %s.\n", THIS_MODULE->name, name);
    return safe_size_orig;  /* error */
  }
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

/**
 * Define a function and the corresponding anchor structure, whose .prev
 * field can be used to call the original function. A SETUP_HOOK is also
 * needed in order for this to work. function_name must be a kernel function
 * exported with EXPORT_SYMBOL.
 *
 * Good gcc type checking if function_name doesn't have __VA_ARGS__:
 * warning: initialization from incompatible pointer type
 */
#define DEFINE_ANCHOR(return_type, function_name, ...) \
  /* Declare function to get a compile error on conflict. */ \
  extern return_type function_name(__VA_ARGS__); \
  static return_type function_name##__repl(__VA_ARGS__); \
  static struct { \
    /* Call this within DEFINE_ANCHOR(foo):
     * foo__anchor.prev(...)
     */ \
    return_type (*prev)(__VA_ARGS__); \
    return_type (*orig_function)(__VA_ARGS__); \
    return_type (*replacement_function)(__VA_ARGS__); \
    char *name; \
  } function_name##__anchor = { \
    .prev = NULL, \
    .orig_function = function_name,  /* warn on type error or undefined symbol */ \
    .replacement_function = function_name##__repl, \
    .name = #function_name, \
  }; \
  static return_type function_name##__repl(__VA_ARGS__)

#define SETUP_HOOK(function_name, i) \
  set_hook( \
      /*orig_function:*/(char*)function_name##__anchor.orig_function, \
      /*replacement_function:*/(char*)function_name##__anchor.replacement_function, \
      /*name:*/function_name##__anchor.name, \
      /*hook:*/rmtimeup_hooks + (i), \
      /*prev_out:*/(char**)&function_name##__anchor.prev)

#if USE_SPRINT_SYMBOL
/** Return pointer to kernel symbol with name, which is at most 32768 bytes
 * away from `nearby' -- or NULL if not found.
 *
 * @param name must be a symbol name, e.g. "do_mount"
 * @param nearby must be an exported symbol (without quotes), e.g. mnt_pin
 */
static __always_inline char *my_lookup_name_detail(
    char *name, void *nearby, unsigned long range, unsigned long step) {
  unsigned long lbase = (unsigned long)nearby, l;
  unsigned long lmin = lbase <= range ? 0 : lbase - range;
  unsigned long lmax = lbase + range < lbase ? 0UL - 1 : lbase + range;
  long m;
  char buffer[KSYM_SYMBOL_LEN];
  char nameat[64];
  int nameatlen;
  strncpy(nameat, name, sizeof(nameat));
  nameat[sizeof(nameat) - 1] = '\0';
  nameatlen = strlen(nameat) + 3;
  strcpy(nameat + nameatlen - 3, "+0x");
  for (l = lmin; l <= lmax; l += step) {
    sprint_symbol(buffer, l);
    /* Now buffer is something like "do_mount+0xf1..." */
    if (0 == strncmp(buffer, nameat, nameatlen)) {
      if (1 != sscanf(buffer + nameatlen - 2, "%li", &m)) return NULL;
      return (char*)(l - m);
    }
  }
  return NULL;  /* not found */
}

static __always_inline char *my_lookup_name(char *name, void *nearby) {
  /* We assume that the function machine code is at least 64 bytes long, so
   * we set step to 64.
   * set_kernel_text_ro() is exactly 64 bytes long.
   */
  return my_lookup_name_detail(name, nearby, /*range:*/32768, /*step:*/64);
}
#else
static __always_inline char *my_lookup_name(char *name, void *nearby) {
  (void)nearby;
  return (char*)kallsyms_lookup_name(name);
}
#endif

/**
 * Like DEFINE_ANCHOR, but to be used with SETUP_HOOK_KALLSYMS, which fetches
 * the symbol using my_lookup_name. This works even for functions
 * without EXPORT_SYMBOL (such as do_mount and umount_tree).
 */
#define DEFINE_ANCHOR_KALLSYMS(return_type, function_name, ...) \
  /* Declare function to get a compile error on conflict. */ \
  extern return_type function_name(__VA_ARGS__); \
  static return_type function_name##__repl(__VA_ARGS__); \
  static struct { \
    /* Call this within DEFINE_ANCHOR(foo):
     * foo__anchor.prev(...)
     */ \
    return_type (*prev)(__VA_ARGS__); \
    return_type (*orig_function)(__VA_ARGS__); \
    return_type (*replacement_function)(__VA_ARGS__); \
    char *name; \
  } function_name##__anchor = { \
    .prev = NULL, \
    .orig_function = function_name + 1 ? NULL : NULL,  /* warn on type error or undefined symbol */ \
    .replacement_function = function_name##__repl, \
    .name = #function_name, \
  }; \
  static return_type function_name##__repl(__VA_ARGS__)

#define SETUP_HOOK_KALLSYMS(function_name, nearby, i) \
  ({ \
    function_name##__anchor.orig_function = (void*)my_lookup_name(#function_name, (void*)nearby); \
    SETUP_HOOK(function_name, i); \
  })

/* --- */

DEFINE_ANCHOR(int, vfs_rename,
    struct inode *old_dir, struct dentry *old_dentry VFSMNT_TARG(old_mnt),
    struct inode *new_dir, struct dentry *new_dentry VFSMNT_TARG(new_mnt)) {
  int prevret;
  struct dentry *old_dentry_parent = dget(old_dentry->d_parent);
  struct dentry *nolock1 = old_dentry_parent;
  char is_dir = old_dentry->d_inode ?
      S_ISDIR(old_dentry->d_inode->i_mode) : 0;
  struct dentry *new_dentry_parent = dget(new_dentry->d_parent);
  struct dentry *nolock2 = new_dentry_parent;
  char had_root = IS_ROOT(old_dentry) || IS_ROOT(new_dentry);
  char old_dentry_name[NAME_MAX + 1], new_dentry_name[NAME_MAX + 1];
  struct timespec now;

  PRINT_DEBUG("my vfs_rename called\n%s", "");

  memcpy(old_dentry_name, old_dentry->d_name.name, old_dentry->d_name.len);
  old_dentry_name[old_dentry->d_name.len] = '\0';

  memcpy(new_dentry_name, new_dentry->d_name.name, new_dentry->d_name.len);
  new_dentry_name[new_dentry->d_name.len] = '\0';

  prevret = vfs_rename__anchor.prev(
      old_dir, old_dentry VFSMNT_ARG(old_mnt),
      new_dir, new_dentry VFSMNT_ARG(new_mnt));
  PRINT_DEBUG("my vfs_rename prevret=%d\n", prevret);
  if (prevret == 0 && !had_root &&
      has_dentry_tagdb(new_dentry_parent->d_sb, nolock1, nolock2)) {
    /* At this point, get_path(old_dentry) and get_path(new_dentry) don't
     * give the same pathnames as what they gave before the
     * vfs_rename__anchor.prev call, but their parents are still the same
     * and valid (but the {old,new}->d_parent pointers have swapped).
     *
     * So we reuse (old_dentry_parent, old_entry_name) and
     * (new_dentry_parent, new_entry_name) here.
     */
    old_dentry = old_dentry_parent;
    if (is_dir) {
      /* If the original old_dentry was a directory, we descend here to
       * update its mtime (and then its parent's mtime, and then up to the
       * root). Otherwise we'll update its parent's mtime (and then up to the
       * root).
       */
      /* We don't need mutex_lock(&old_dentry_parent->d_inode->i_mutex) here,
       * it is already locked in fs/namei.c:lock_rename(). We get a deadlock
       * if we try to lock it again.
       */
      old_dentry_parent = lookup_one_len(old_dentry_name, old_dentry,
          strlen(old_dentry_name));
      if (IS_ERR(old_dentry_parent) || old_dentry_parent->d_inode == NULL) {
        old_dentry_parent = old_dentry;
      } else {
        dput(old_dentry);  /* we'll do dput(old_dentry_parent) later */
      }
    }

    now = current_fs_time(old_dentry_parent->d_sb);
    update_mtimes(old_dentry_parent, now, nolock1, nolock2);

    new_dentry = new_dentry_parent;
    if (is_dir) {
      new_dentry_parent = lookup_one_len(new_dentry_name, new_dentry,
          strlen(new_dentry_name));
      if (IS_ERR(new_dentry_parent) || new_dentry_parent->d_inode == NULL) {
        new_dentry_parent = new_dentry;
      } else {
        dput(new_dentry);  /* we'll do dput(new_dentry_parent) later */
      }
    }
    update_mtimes(new_dentry_parent, now, nolock1, nolock2);

    notify_rmtimeup_events(EVENT_FILES_CHANGED);
  }
  dput(new_dentry_parent);
  dput(old_dentry_parent);
  return prevret;  
}

DEFINE_ANCHOR(int, vfs_link,
              struct dentry *old_dentry VFSMNT_TARG(old_mnt),
              struct inode *dir,
              struct dentry *new_dentry VFSMNT_TARG(new_mnt)) {
  int prevret;
  struct dentry *old_dentry_parent = old_dentry->d_parent;
  struct dentry *new_dentry_parent = new_dentry->d_parent;
  struct timespec now;

  PRINT_DEBUG("my vfs_link called\n%s", "");
  prevret = vfs_link__anchor.prev(
      old_dentry VFSMNT_ARG(old_mnt), dir, new_dentry VFSMNT_ARG(new_mnt));
  PRINT_DEBUG("my vfs_link prevret=%d\n", prevret);
  if (prevret == 0 &&
      has_dentry_tagdb(new_dentry_parent->d_sb,
          /*nolock1:*/new_dentry_parent, /*nolock2:*/new_dentry_parent)) {
    now = current_fs_time(old_dentry_parent->d_sb);
    update_mtimes(old_dentry_parent, now,
        /*nolock1:*/old_dentry_parent, /*nolock2:*/new_dentry_parent);
    update_mtimes(new_dentry_parent, now,
        /*nolock1:*/old_dentry_parent, /*nolock2:*/new_dentry_parent);
    notify_rmtimeup_events(EVENT_FILES_CHANGED);
  }
  return prevret;  
}

DEFINE_ANCHOR(int, vfs_unlink,
              struct inode *dir,
              struct dentry *dentry VFSMNT_TARG(mnt)) {
  int prevret;
  struct timespec now;
  struct dentry *dentry_parent = dentry->d_parent;

  PRINT_DEBUG("my vfs_unlink called\n%s", "");
  prevret = vfs_unlink__anchor.prev(dir, dentry VFSMNT_ARG(mnt));
  PRINT_DEBUG("my vfs_unlink prevret=%d\n", prevret);
  if (prevret == 0 &&
      has_dentry_tagdb(dentry_parent->d_sb,
          /*nolock1:*/dentry_parent, /*nolock2:*/dentry_parent)) {
    now = current_fs_time(dentry_parent->d_sb);
    /* TODO: improve speed by omitting update_mtimes if an uninteresting file
     * is being removed (i.e. nlink == 1, no user.* tags). Also do this
     * optimization for the other anchor functions.
     */
    update_mtimes(dentry_parent, now,
        /*nolock1:*/dentry_parent, /*nolock2:*/dentry_parent);
    notify_rmtimeup_events(EVENT_FILES_CHANGED);
  }
  return prevret;
}

DEFINE_ANCHOR(int, vfs_setxattr,
              struct dentry *dentry VFSMNT_TARG(mnt),
              vfs_name_t name, vfs_value_t value,
              size_t size, int flags FILE_TARG(filp)) {
  /* corresponding command: setfattr -n user.foo -v bar t1.jpg */
  int prevret;
  struct timespec now;
  struct dentry *dentry_parent = dentry->d_parent;

  PRINT_DEBUG("my vfs_setxattr called\n%s", "");
  prevret = vfs_setxattr__anchor.prev(dentry VFSMNT_ARG(mnt), name, value,
      size, flags VFSMNT_ARG(filp));
  PRINT_DEBUG("my vfs_setxattr prevret=%d name=%s flags=0x%x\n", prevret, name,
              (prevret == 0) << 0 |
              S_ISREG(dentry->d_inode->i_mode) << 1 |
              (0 == strncmp(name, "user.", 5)) << 2 |
              has_dentry_tagdb(dentry_parent->d_sb, dentry_parent, dentry_parent) << 3);
  if (prevret == 0 && S_ISREG(dentry->d_inode->i_mode) &&
      0 == strncmp(name, "user.", 5) &&  /* caller has done copy_from_user */
      has_dentry_tagdb(dentry_parent->d_sb,
          /*nolock1:*/dentry_parent, /*nolock2:*/dentry_parent)) {
    now = current_fs_time(dentry_parent->d_sb);
    update_mtimes(dentry_parent, now,
        /*nolock1:*/dentry_parent, /*nolock2:*/dentry_parent);
    notify_rmtimeup_events(EVENT_FILES_CHANGED);
  }
  return prevret;
}

DEFINE_ANCHOR(int, vfs_removexattr,
              struct dentry *dentry VFSMNT_TARG(mnt),
              vfs_name_t name FILE_TARG(filp)) {
  /* corresponding command: setfattr -x user.foo t1.jpg */
  int prevret;
  struct timespec now;
  struct dentry *dentry_parent = dentry->d_parent;

  PRINT_DEBUG("my vfs_removexattr called\n%s", "");
  prevret = vfs_removexattr__anchor.prev(dentry VFSMNT_ARG(mnt),
      name VFSMNT_ARG(filp));
  PRINT_DEBUG("my vfs_removexattr prevret=%d\n", prevret);
  if (prevret == 0 && S_ISREG(dentry->d_inode->i_mode) &&
      0 == strncmp(name, "user.", 5) &&  /* caller has done copy_from_user */
      has_dentry_tagdb(dentry_parent->d_sb,
          /*nolock1:*/dentry_parent, /*nolock2:*/dentry_parent)) {
    now = current_fs_time(dentry_parent->d_sb);
    update_mtimes(dentry_parent, now,
        /*nolock1:*/dentry_parent, /*nolock2:*/dentry_parent);
    notify_rmtimeup_events(EVENT_FILES_CHANGED);
  }
  return prevret; 
}

DEFINE_ANCHOR_KALLSYMS(long, do_mount,
              char *dev_name, char *dir_name, char *type_page,
              unsigned long flags, void *data_page) {
  /* This function is also called for -o remount */
  /* correponding command: mount -t $type_page $dev_name $dir_name */
  long prevret;
  PRINT_DEBUG("my do_mount dev_name=(%s) dir_name=(%s) called\n",
      dev_name, dir_name);
  prevret = do_mount__anchor.prev(dev_name, dir_name, type_page,
      flags, data_page);
  PRINT_DEBUG("my do_mount dev_name=(%s) dir_name=(%s) prevret=%ld\n",
      dev_name, dir_name, prevret);
  if (prevret == 0) {
    notify_rmtimeup_events(EVENT_MOUNTS_CHANGED);
  }
  return prevret;
}

/* since 2.6.31 (or earlier) the umount_tree() declaration is not exported,
 * but its defined in the private header file fs/internal.h
 */
extern void umount_tree(struct vfsmount *mnt, int propagate,
                        struct list_head *kill);

DEFINE_ANCHOR_KALLSYMS(void, umount_tree,
              struct vfsmount *mnt, int propagate, struct list_head *kill) {
  PRINT_DEBUG("my umount_tree called\n%s", "");
  umount_tree__anchor.prev(mnt, propagate, kill);
  PRINT_DEBUG("my umount_tree returned\n%s", "");
  notify_rmtimeup_events(EVENT_MOUNTS_CHANGED);
}

/* --- */

#define MAX_RMTIMEUP_HOOKS 8
static DEFINE_SPINLOCK(hooks_lock);
static struct hook *rmtimeup_hooks = NULL;

static char undo_all_hooks(void) {
  int i;
  char do_keep = 0;
  for (i = 0; i < MAX_RMTIMEUP_HOOKS; ++i) {
    if (undo_hook(rmtimeup_hooks + i)) do_keep = 1;
  }
  return do_keep;
}

static void (*my_set_kernel_text_ro)(void) = NULL;
static void (*my_set_kernel_text_rw)(void) = NULL;

#if USE_EXTERN_PAGE_KERNEL_EXEC
unsigned long long *my_page_kernel_exec = NULL;
#undef  __PAGE_KERNEL_EXEC
#define __PAGE_KERNEL_EXEC (*my_page_kernel_exec)
#endif

static int init_hooks(void) {
  unsigned long irq_flags;
  int error;

#if USE_EXTERN_PAGE_KERNEL_EXEC
  if (my_page_kernel_exec == NULL) {
    if (sizeof(__PAGE_KERNEL) != sizeof(*my_page_kernel_exec)) {
      printk(KERN_ERR "%s: size mismatch: sizeof(__PAGE_KERNEL_EXEC)=%d "
             " sizeof(__PAGE_KERNEL)=%d", THIS_MODULE->name,
             sizeof(*my_page_kernel_exec), sizeof(__PAGE_KERNEL));
      error = -EINVAL;
      goto do_exit;
    }
    my_page_kernel_exec = (unsigned long long*)my_lookup_name_detail(
        "__PAGE_KERNEL_EXEC", &__PAGE_KERNEL, 64, 4);
    if (my_page_kernel_exec == NULL) {
      printk(KERN_ERR "%s: missing __PAGE_KERNEL_EXEC\n", THIS_MODULE->name);
      error = -ENOKEY;
      goto do_exit;
    }
  }
#endif

  if (NULL == (rmtimeup_hooks = __vmalloc(
      MAX_RMTIMEUP_HOOKS * sizeof*rmtimeup_hooks, GFP_KERNEL,
      PAGE_KERNEL_EXEC))) {
    error = -ENOMEM;
    goto do_exit;
  }
  memset(rmtimeup_hooks, '\0', MAX_RMTIMEUP_HOOKS * sizeof*rmtimeup_hooks);
  /* Kernel 2.6.31-20 in Ubuntu Karmic disables write access to kernel code
   * (e.g. see ``Write protecting the kernel text'' and ``Write protecting
   * the kernel read-only data'' in dmesg(1)), but it provides
   * set_kernel_text_rw() (enabled by CONFIG_DEGUG_RODATA=y), which we use
   * here to make our modifications in SETUP_HOOK/set_hook.
   * 
   * set_kernel_text_rw() doesn't work when IRQs are disabled, so we don't
   * do any locking here (wich is a little bit unsafe).
   */
  if (my_set_kernel_text_ro && my_set_kernel_text_rw) {
    printk(KERN_INFO "%s: using set_kernel_text_rw()\n", THIS_MODULE->name);
    my_set_kernel_text_rw();
  }
  spin_lock_irqsave(&hooks_lock, irq_flags);  /* Imp: smaller lock */
  /* If you add hooks, don't forget to increase MAX_RMTIMEUP_HOOKS */
  if (0 != (error = SETUP_HOOK(vfs_rename, 0)) ||
      0 != (error = SETUP_HOOK(vfs_unlink, 1)) ||
      0 != (error = SETUP_HOOK(vfs_link, 2)) ||
      0 != (error = SETUP_HOOK(vfs_setxattr, 3)) ||
      0 != (error = SETUP_HOOK(vfs_removexattr, 4)) ||
      0 != (error = SETUP_HOOK_KALLSYMS(do_mount, /*nearby:*/mnt_pin, 5)) ||
      0 != (error = SETUP_HOOK_KALLSYMS(umount_tree, /*nearby:*/mnt_pin, 6))) {
    undo_all_hooks();
    goto do_unlock;
  }
  error = 0;
 do_unlock:
  spin_unlock_irqrestore(&hooks_lock, irq_flags);
  if (my_set_kernel_text_ro && my_set_kernel_text_rw)
    my_set_kernel_text_ro();
 do_exit:
  return error;
}

static void exit_hooks(void) {
  char do_keep;
  unsigned long irq_flags;
  if (my_set_kernel_text_ro && my_set_kernel_text_rw)
    my_set_kernel_text_rw();
  /* TODO: add mutex in case of removing the module while a vfs_rename is
   * in progress. lock_kernel() or preempt.h? Is this possible?
   */
  spin_lock_irqsave(&hooks_lock, irq_flags);  /* Imp: smaller lock */
  do_keep = undo_all_hooks();
  spin_unlock_irqrestore(&hooks_lock, irq_flags);
  if (my_set_kernel_text_ro && my_set_kernel_text_rw)
    my_set_kernel_text_ro();
  if (do_keep) {
    /* Keep rmtimeup_hooks if we couldn't unhook everything. */
    printk(KERN_WARNING "%s: %d bytes leaked when unloading\n",
        THIS_MODULE->name, sizeof*rmtimeup_hooks);
  } else {
    vfree(rmtimeup_hooks);
  }
}

static int __init init_rmtimeup(void) {
  struct proc_dir_entry *p;
  int ret;

  printk(KERN_INFO "%s: version "RMTIMEUP_VERSION" loading\n",
      THIS_MODULE->name);
  PRINT_DEBUG("hello, version "RMTIMEUP_VERSION" loading\n%s", "");

  {
    extern void ioremap_nocache(void);
    my_set_kernel_text_ro =
        (void*)my_lookup_name("set_kernel_text_ro", (char*)ioremap_nocache);
    my_set_kernel_text_rw =
        (void*)my_lookup_name("set_kernel_text_rw", (char*)ioremap_nocache);
  }

  ret = init_hooks();
  if (ret) goto done;

  p = create_proc_entry("rmtimeup-event", 0444, NULL);  /* for all users */
  if (!p) { ret = -ENOMEM; goto done; }
#if USE_MODULE_OWNER
  p->owner = THIS_MODULE;
#endif
  SETPROC_OPS(p, rmtimeup_event_ops);

  ret = 0;
  printk(KERN_INFO "%s: version "RMTIMEUP_VERSION" loaded OK\n",
      THIS_MODULE->name);
 done:
  return ret;
}

/*
 * exit_rmtimeup()
 */
static void __exit exit_rmtimeup(void) {
  /* exit_rmtimeup doesn't get called if /proc/rmtimeup-event is open. */
  remove_proc_entry("rmtimeup-event", 0);
  exit_hooks();
  printk(KERN_INFO "%s: unloaded\n", THIS_MODULE->name);
}

module_init(init_rmtimeup);
module_exit(exit_rmtimeup);
