/* 
 * mainmod.c -- main source file for the rmtimeup Linux kernel module
 * kernel module for 2.6.x kernels (tested with 2.6.18.1 and 2.6.22.1)
 * by pts@fazekas.hu at Sat Jan  3 15:41:02 CET 2009
 *
 * rmtimeup is a Linux i386 (x86) 32-bit kernel module which updates the
 * mtime of all ancestor directories for all interesting file operations:
 * rename, unlink, link, setxattr on files. To do this, it registers itself
 * as a security handler (LSM -- Linux security module). rmtimeup can be used
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
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/moduleparam.h>

#include <linux/security.h>
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

/* --- fake_entry */

/** origret is the original return value of the caller */
typedef int (*fakecallback_t)(int origret,
    void *ptr0, void *ptr1, void *ptr2, void *ptr3, void *ptr4);

/** A struct containing (Imp: ...), and also an
 * executable machine code which calls wrapped_cont.
 *
 * See also assert(sizeof(struct fake_entry) ...);
 */
struct fake_entry {
  /** Instruction pointer in .text where caller of caller continues. */
  char *grandcallercont;
  /** Callback function to be called when caller returns (just before grandcallercont) */
  fakecallback_t fakecallback;
  /** Where to put fake_trampoline/fakecallback on the stack: the difference
   * in disassembly: esp - esp0.
   */
  long espdiff;
  /** Instruction pointer in .text where caller continues. */
  char *callercont;
};

struct fake_entry fes[200];
unsigned fesi = 0, fesc = 0;
/* Imp: use a read-write lock */
spinlock_t fes_lock;

static struct fake_entry *find_fake_entry(
    fakecallback_t fakecallback, char *callercont) {
  /* TODO: try to do this with a 200-element linked list */
  struct fake_entry *fe = NULL;
  unsigned i;
  for (i = 0; i < fesc; ++i) {
    fe = fes + i;
    if (fe->callercont == callercont && fe->fakecallback == fakecallback) return fe;
  }
  return NULL;
}

static struct fake_entry *add_fake_entry(
    char *grandcallercont, fakecallback_t fakecallback,
    long espdiff, char *callercont) {
  struct fake_entry *fe = NULL;
  unsigned i;
  unsigned long irq_flags;
  for (i = 0; i < fesc; ++i) {
    fe = fes + i;
    if (fe->callercont == callercont && fe->fakecallback == fakecallback) {
      assert(fe->grandcallercont == grandcallercont);
      assert(fe->espdiff == espdiff);
      break;
    }
  }
  printk(KERN_INFO "i=%d fesc=%d\n", i, fesc);
  if (i == fesc) {  /* not found */
    spin_lock_irqsave(&fes_lock, irq_flags);
    fe = fes + fesi;
    ++fesi;
    if ((char*)fes + sizeof(fes) == (char*)(fes + fesi)) {  /* end of table */
      fesi = 0;
    } else if (fesi > fesc) {
      ++fesc;
    }
    /* Imp: what if we're just ruining someone else's linear search above? */
    fe->grandcallercont = grandcallercont;
    fe->fakecallback = fakecallback;
    fe->espdiff = espdiff;
    fe->callercont = callercont;
    spin_unlock_irqrestore(&fes_lock, irq_flags);
  }
  /* TODO: unlock */
  return fe;
}

static void init_fes(void) {
  spin_lock_init(&fes_lock);
  fesi = fesc = 0;
}

/* --- origarg_entry */

struct origarg_entry {
  struct list_head list;
  void *key;  /* be last so it is moved last in delete_origarg_entry */
  void *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;
  /** Instruction pointer in .text where caller of caller continues. */
  char *grandcallercont;
  fakecallback_t fakecallback;
};

struct list_head origarg_entry_list;  /* Imp: move this to shared */
spinlock_t oes_lock;

/** Also calls kfree(oe) */
static void delete_origarg_entry(struct origarg_entry *oe) {
  unsigned irq_flags;
  assert(oe);
  if (oe) {
    assert(oe->key != NULL);
    spin_lock_irqsave(&oes_lock, irq_flags);
    oe->key = NULL;
    list_del(&oe->list);
    kfree(oe);
    spin_unlock_irqrestore(&oes_lock, irq_flags);
  }
}

/** Returns NULL on out of memory (-ENOMEM) */
static struct origarg_entry *add_origarg_entry(
    void *key, void *ptr0, void *ptr1, void *ptr2, void *ptr3, void *ptr4,
    char *grandcallercont, fakecallback_t fakecallback) {
  struct list_head *pos;
  struct origarg_entry *oe = NULL;
  unsigned irq_flags;
  assert(key != NULL);
  spin_lock_irqsave(&oes_lock, irq_flags);
  list_for_each(pos, &origarg_entry_list) {
    oe = (struct origarg_entry*)pos; /* list_entry(pos, struct origarg_entry, list) */
    if (oe->key == key) break;
    oe = NULL;
  }
  printk(KERN_INFO "add_origarg_entry key=%p oe=%p\n", key, oe);
  if (oe == NULL) {  /* not found */
    if (NULL == (oe = kmalloc(sizeof*oe, GFP_KERNEL))) goto unlock;
  }
  list_add(&oe->list, &origarg_entry_list);  /* beginning */
  oe->key = key;
  oe->ptr0 = ptr0;
  oe->ptr1 = ptr1;
  oe->ptr2 = ptr2;
  oe->ptr3 = ptr3;
  oe->ptr4 = ptr4;
  oe->grandcallercont = grandcallercont;
  oe->fakecallback = fakecallback;
 unlock:
  spin_unlock_irqrestore(&oes_lock, irq_flags);
  return oe;
}

static struct origarg_entry *find_origarg_entry(void *key) {
  struct list_head *pos;
  struct origarg_entry *oe;
  assert(key != NULL);
  list_for_each(pos, &origarg_entry_list) {
    oe = (struct origarg_entry*)pos; /* list_entry(pos, struct origarg_entry, list) */
    if (oe->key == key) return oe;
  }
  return NULL;
}

static void init_oes(void) {
  spin_lock_init(&oes_lock);
  INIT_LIST_HEAD(&origarg_entry_list);
}

/* --- RETURN_WRAP support */

/** Define return-wrapped function named function_name returning return_type
 * (almost always int), having storage class storage (e.g. static) and
 * arguments `...'.
 *
 * A return-wrapped can register a callback which will be called when the
 * caller of the return-wrapped function returns. This only works for the call
 * pattern if (return_wrapped(...)) { ... } in the caller. The callback must
 * be of type fakecallback_t.
 *
 * This mechanism works only on i386 and gcc -mregparm=3.
 *
 * Example:
 *
 *   static int mycallback(int origret,
 *         void *ptr0, void *ptr1, void *ptr2, void *ptr3, void *ptr4) {
 *     printk(KERN_INFO "mycallback origret=%d ptr0=%p", origret, ptr0);
 *     return origret;
 *   }
 *
 *   static int myfunction(int a, int b);  // optional declaration
 *
 *   RETURN_WRAP(static, int, myfunction, int a, int b) {
 *     printk(KERN_INFO "myfunction a=0x%x b=0x%x", a, b);
 *     if (a < 0) return -EINVAL;
 *     RETURN_WITH_CALLBACK_REGISTER((void*)a, (void*)b, 0, 0, mycallback);
 *   }
 *  
 */
#define RETURN_WRAP(storage, return_type, function_name, ...) \
    static return_type function_name##__pre( \
        char *ebp, char *esp0, char *eip, char *cont, __VA_ARGS__); \
    /* This trampoline works with gcc -mregparm=3 (Linux kernel fastcall) */ \
    static struct { char pre[30]; char *wrapped; char post[1]; } \
    __attribute__ ((packed)) \
    function_name##__trdata __attribute__((section("text"))) = { \
      /* (eax = ptr0) (edx = ptr1) (ecx = ptr2) (cont @ esp0 - 4) (ptr3) */ \
      /*00000000*/ "\x87\x0C\x24" /* xchg ecx,[esp] */ \
      /*00000003*/ "\x52" /* push edx */ \
      /*00000004*/ "\x50" /* push eax */ \
      /*00000005*/ "\x51" /* push ecx */ \
      /*00000006*/ "\x89\xE8" /* mov eax,ebp */ \
      /*00000008*/ "\x8D\x54\x24\x10" /* lea edx,[esp+0x10]  ; esp after return of trampoline */ \
      /* (eax = ebp0) (edx = esp0) (ecx = [esp0]) (cont.trampoline) (cont) (ptr0) (ptr1) (ptr2) (ptr3) */ \
      /*0000000C*/ "\xE8\x0C\x00\x00\x00" /* call 0x1d */ \
      /* (eax = retval) (cont) (ptr0) (ptr1) (ptr2) (ptr3) */ \
      /*00000011*/ "\x89\x44\x24\x08" /* mov [esp+0x8],eax  ; save retval */ \
      /*00000015*/ "\x58" /* pop eax */ \
      /* (eax = cont) (ptr0) (retval) (ptr2) (ptr3) */ \
      /*00000016*/ "\x89\x44\x24\x08" /* mov [esp+0x8],eax  ; save cont */ \
      /*0000001A*/ "\x58" /* pop eax */ \
      /* (retval) (cont) (ptr3) */ \
      /*0000001B*/ "\x58" /* pop eax  ; retval */ \
      /*0000001C*/ "\xC3" /* ret */ \
      /*0000001D*/ "\x68", /* push dword 0x12345678 */ \
      (char*)&(function_name##__pre),  /* we need this because we cannot be suore of -fno-toplevel-reorder */ \
      "\xC3"  /* ret */ \
    }; \
    storage return_type function_name(__VA_ARGS__) \
        __attribute__((alias(#function_name "__trdata"))); \
    static return_type function_name##__pre( \
        char *wrap__ebp, char *wrap__esp0, char *wrap__eip, \
        char *cont __attribute__((unused)), \
        __VA_ARGS__)

/** See thedocumentation of RETURN_WRAP. */
#define RETURN_WITH_CALLBACK_REGISTER(ptr0, ptr1, ptr2, ptr3, ptr4, fakecallback) \
  do { return register_callback_on_caller_return( \
      ptr0, ptr1, ptr2, ptr3, ptr4, fakecallback, \
      wrap__ebp, wrap__esp0, wrap__eip); } while(0)

static int fake_trampoline(int origret, char *dummy_edx, char *dummy_ecx, char *dummy_stackarg) {
  struct origarg_entry *oe, oecp;
  asm("sub $0x4, %esp");  /* make place for the return address (will be set to oe->grandcallercont) */
  asm("mov %eax, (%esp)");  /* !! Imp: get rid of this; there is a mov %eax, (%esp) autogenerated above our sub */
  /* origret contains eax because of fastcall calling convention */
  oe = find_origarg_entry(/*esp:*/(char*)((&dummy_stackarg)-1));
  assert(oe && "origarg_entry not found for fake_trampoline");
  printk(KERN_INFO "FAKE origret=%d esp=%lx oe=%lx\n",
      origret, (long)(char*)((&dummy_stackarg)-1), (long)oe);
  assert(__builtin_return_address(0) == (&dummy_stackarg)[-1]);
  (&dummy_stackarg)[-1] = oe->grandcallercont;  /* override return address */
  oecp = *oe;
  delete_origarg_entry(oe);
#if 0
  asm("push $0x22222222");  /* a push dword instruction */
  asm("push $-5");  /* a push byte instruction */
  asm("pop %eax");
  asm("pop %eax");
#endif
  return oecp.fakecallback(origret,
      oecp.ptr0, oecp.ptr1, oecp.ptr2, oecp.ptr3, oecp.ptr4);
}

/** @return 0 or -ENOMEM etc. */
static int register_callback_on_caller_return(
    void *ptr0, void *ptr1, void *ptr2, void *ptr3, void *ptr4,
    fakecallback_t fakecallback,
    char *ebp, char *esp0, char *eip) {
  /* Imp: add x86-64 (amd64) support */
  /* Imp: uint64_t for pointer to integer conversion (instead of long) */
  unsigned left0 = 100, left, checkleft, framesleft = 2;
  struct fake_entry *fe;
  long delta;  /* we assume: sizeof(long) >= sizeof(char*) */
  int consumed, got;
  int checkstate;
  char *eip_frame;
  char *esp = esp0;
  /** Disassembled instruction */
  char *dins;
  char *dinsend;
  ud_t ud_obj;

  printk(KERN_INFO "reg_callerret ebp=%lx esp0=%lx eip=%lx fakecallback=%p\n",
      (long)ebp, (long)esp0, (long)eip, fakecallback);

  if (NULL != (fe = find_fake_entry(
      /*fakecallback:*/fakecallback, /*callercont:*/eip))) {
    /* already disassembled, no need to disassemble again */
    esp = esp0 + fe->espdiff;
    printk(KERN_INFO "fake entry fe=%lx esp=%lx found\n", (long)fe, (long)esp);
   do_return:
    if (NULL == add_origarg_entry(/*key:*/esp,
        ptr0, ptr1, ptr2, ptr3, ptr4, fe->grandcallercont, fakecallback)) {
      return -ENOMEM;
    }
    /* Redirect `ret' in caller to fake_trampoline */
    *(char**)esp = (char*)fake_trampoline;
    return 0;
  }

  ud_init(&ud_obj);
  /* ud_set_input_buffer(&ud_obj, "\x41\x42\xC3\x90", 4); */
  /* at most left # instructions ==> at most left # bytes */
  ud_set_mode(&ud_obj, 32); /* Imp: sizeof(long) * 8 */
  ud_set_syntax(&ud_obj, UD_SYN_INTEL);

  /* We are doing an abstract interpretation of the disassebly of the caller
   * in order to find out esp when it returns.
   */
  left = left0;
  eip_frame = eip;
 next_frame:
  while (framesleft > 0) { 
    --framesleft;
    /* Check that the caller has an if (error) ... statement following */
    checkstate = 1;
    checkleft = left0 * 0 + 5;
    ud_set_input_buffer(&ud_obj, (void*)eip_frame, left);
    ud_set_pc(&ud_obj, (unsigned long)eip_frame); /* for proper jump/call offsets */
    while (checkleft > 0 && ud_disassemble(&ud_obj)) {
      --checkleft;
      dins = ud_insn_asm(&ud_obj);
      dinsend = dins + strlen(dins);
      if (dinsend != dins && dinsend[-1] == ' ') --dinsend;
      *dinsend = '\0'; /* remove trailing space from "ret " etc. */
      printk(KERN_INFO "C%08lx  %s;\n", (unsigned long)ud_insn_off(&ud_obj), dins);
      if (checkstate == 1 && 0 == strncmp(dins, "mov ", 4)) {
      } else if (checkstate == 1 && 0 == strncmp(dins, "pop ", 4)) { /* !! kernel */
      } else if (checkstate == 1 && 0 == strncmp(dins, "cmp ", 4) &&
                 (dinsend - dins) >= 10 && 0 == strcmp(dinsend - 5, ", 0x0")) {
        checkstate = 2;
      } else if (checkstate == 1 && 0 == strcmp(dins, "test eax, eax")) {
        checkstate = 2;
      } else if (checkstate == 1 && 0 == strcmp(dins, "test ebx, ebx")) { /* !! other regs */
        checkstate = 2;
      } else if (checkstate == 2 && (0 == strncmp(dins, "jz ", 3) ||
                                     0 == strncmp(dins, "jnz ", 4))) {
        checkstate = 0;  /* found the right frame */
        break;
      } else {
        checkstate = 3;
        break;
      }
    }
    printk(KERN_INFO "checkstate == %d\n", checkstate);

    /* Abstract interpretation of the current stack frame */
    ud_set_input_buffer(&ud_obj, (void*)eip_frame, left);
    ud_set_pc(&ud_obj, (unsigned long)eip_frame); /* for proper jump/call offsets */
    while (left > 0 && ud_disassemble(&ud_obj)) {
      --left;
      dins = ud_insn_asm(&ud_obj);
      dinsend = dins + strlen(dins);
      if (dinsend != dins && dinsend[-1] == ' ') --dinsend;
      *dinsend = '\0'; /* remove trailing space from "ret " etc. */
      /* ud_insn_off displays pointers */
      printk(KERN_INFO "%08lx  %s;\n", (unsigned long)ud_insn_off(&ud_obj), dins);
      if (0 == strcmp(dins, "ret")) {
        printk(KERN_INFO "found ret, esp == %lx + %lx == %lx; eip=%lx\n",
           (long)esp0, (long)(esp - esp0), (long)esp, (long)eip);
        assert(esp >= esp0 && "esp too small");
        if (checkstate != 0) {  /* continue with next frame */
          eip_frame = *(char**)esp;
          esp += sizeof(char*);
          goto next_frame;
        }
        /* Imp: 64-bit support */
        fe = add_fake_entry(
            /*grandcallercont:*/*(char**)esp,
            /*fakecallback:*/fakecallback,
            /*espdiff:*/(long)(esp - esp0),
            /*callercont:*/eip);
        goto do_return;
      } else if (0 == strcmp(dins, "pop esp")) {
        /* Imp: bounds check esp */
        esp = *(char**)esp;
      } else if (0 == strcmp(dins, "pop ebp")) {
        /* Imp: bounds check esp */
        ebp = *(char**)esp;
        esp += sizeof(char*);
      } else if (0 == strncmp(dins, "pop ", 4)) {
        /* Imp: increase easp by proper size for pop */
        esp += sizeof(char*);
      } else if (0 == strncmp(dins, "push ", 4)) {
        /* Imp: increase easp by proper size for push */
        esp -= sizeof(char*);
      } else if (0 == strcmp(dins, "mov esp, ebp")) {
        esp = ebp;
      } else if (0 == strcmp(dins, "mov ebp, esp")) {
        ebp = esp;
      } else if (0 == strcmp(dins, "leave")) {
        /* leave === mov esp, ebp; pop ebp */
        esp = ebp;
        /* Imp: bounds check esp */
        ebp = *(char**)esp;
        esp += sizeof(char*);
      } else if (0 == strncmp(dins, "add esp, 0x", 11) ||
                 0 == strncmp(dins, "add esp, -0x", 12)) {
        got = sscanf(dins + 9, "%li%n", &delta, &consumed);
        assert(got > 0);
        assert(dins + 9 + consumed == dinsend);
        esp += delta;  /* Also works for negative delta because of sizeof */
      } else if (0 == strncmp(dins, "sub esp, 0x", 11) ||
                 0 == strncmp(dins, "sub esp, -0x", 12)) {
        got = sscanf(dins + 9, "%li%n", &delta, &consumed);
        assert(got > 0);
        assert(dins + 9 + consumed == dinsend);
        esp -= delta;
      } else if (0 == strncmp(dins, "add ebp, 0x", 11) ||
                 0 == strncmp(dins, "add ebp, -0x", 12)) {
        got = sscanf(dins + 9, "%li%n", &delta, &consumed);
        assert(got > 0);
        assert(dins + 9 + consumed == dinsend);
        ebp += delta;
      } else if (0 == strncmp(dins, "sub ebp, 0x", 11) ||
                 0 == strncmp(dins, "sub ebp, -0x", 12)) {
        got = sscanf(dins + 9, "%li%n", &delta, &consumed);
        assert(got > 0);
        assert(dins + 9 + consumed == dinsend);
        ebp -= delta;
      } else if (0 == strncmp(dins, "mov esp,", 8) ||
                 0 == strncmp(dins, "lea esp,", 8) ||
                 0 == strncmp(dins, "add esp,", 8) ||
                 0 == strncmp(dins, "adc esp,", 8) ||
                 0 == strncmp(dins, "add esp,", 8) ||
                 0 == strncmp(dins, "sub esp,", 8) ||
                 0 == strncmp(dins, "or esp,", 8) ||
                 0 == strncmp(dins, "and esp,", 8) ||
                 0 == strncmp(dins, "xor esp,", 8)) {
        assert(0 && "unsupported change to esp");
      } else if (0 == strncmp(dins, "mov ebp,", 8) ||
                 0 == strncmp(dins, "lea ebp,", 8) ||
                 0 == strncmp(dins, "add ebp,", 8) ||
                 0 == strncmp(dins, "adc ebp,", 8) ||
                 0 == strncmp(dins, "add ebp,", 8) ||
                 0 == strncmp(dins, "sub ebp,", 8) ||
                 0 == strncmp(dins, "or ebp,", 8) ||
                 0 == strncmp(dins, "and ebp,", 8) ||
                 0 == strncmp(dins, "xor ebp,", 8)) {
        assert(0 && "unsupported change to ebp");
      } else if (0 == strncmp(dins, "jmp 0x", 6) ||
                 0 == strncmp(dins, "jnz 0x", 6)) {
        /* The reason why we jump at jnz is that we want if (error) { ... }
         * be true. This is usually compiled as `test eax, eax; jz ...'.
         * jz jumps if eax is 0 (error is false). So we jump when jnz jumps.
         */
        got = sscanf(dins + 4, "%li%n", &delta, &consumed);
        assert(got > 0);
        assert(dins + 4 + consumed == dinsend); /* !! */
        ud_set_input_buffer(&ud_obj, (void*)delta, left);
        ud_set_pc(&ud_obj, (unsigned long)(char*)delta);
      } else if (0 == strncmp(dins, "jmp dword 0x", 12) ||
                 0 == strncmp(dins, "jnz dword 0x", 12)) { /* !! accept dword everywhere */
        /* The reason why we jump at jnz is that we want if (error) { ... }
         * be true. This is usually compiled as `test eax, eax; jz ...'.
         * jz jumps if eax is 0 (error is false). So we jump when jnz jumps.
         */
        got = sscanf(dins + 10, "%li%n", &delta, &consumed);
        assert(got > 0);
        assert(dins + 10 + consumed == dinsend); /* !! why does it assert? */
        ud_set_input_buffer(&ud_obj, (void*)delta, left);
        ud_set_pc(&ud_obj, (unsigned long)(char*)delta);
      }
    }
    assert(0 && "could not find ret");
  }
  assert(0 && "too many frames up");
  return -EINVAL;
}

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

static int rmtimeup_inode_unlink(struct inode *dir, struct dentry * dentry) {
  return 0;
}

static int rmtimeup_inode_link(struct dentry * old_dentry,
                               struct inode *dir, 
                               struct dentry * dentry) {
  return 0;
}
/* !! setxattr */

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
static void update_mtimes_and_dput(struct dentry *dentry,
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

/* --- */

static struct security_operations rmtimeup_security_ops = {
    .inode_unlink        = rmtimeup_inode_unlink,
    .inode_link          = rmtimeup_inode_link,
    .inode_rename        = rmtimeup_inode_rename,
    .inode_post_setxattr = rmtimeup_inode_post_setxattr,
    .inode_removexattr   = rmtimeup_inode_removexattr,
    .sb_mount            = rmtimeup_sb_mount,
    .sb_umount           = rmtimeup_sb_umount,
};

static int mod_register = 0;

static int __init init_rmtimeup(void) {
  int ret;
  printk(KERN_INFO "rmtimeup version "RMTIMEUP_VERSION" loaded\n");
  /* !! only if debugging */
  printk(KERN_DEBUG "rmtimeup hello version "RMTIMEUP_VERSION" loaded\n");

  /* register as security module */
  ret = register_security( &rmtimeup_security_ops );
  mod_register = 0;
  if (ret) {
    if (ret == -EAGAIN) {
      printk(KERN_ERR"rmtimeup: Another security module is active.\n");
    }
    /* Basic support for stacking below an existing security module */
    ret = mod_reg_security(MOD_REG_NAME, &rmtimeup_security_ops);
    if (ret != 0) {
      printk(KERN_ERR"Failed to register rmtimeup module with"
          " the kernel\n");
      goto no_lsm;
    }
    mod_register = 1;
  }

  init_fes();  /* Imp: return error code */
  init_oes();

 no_lsm:
  return ret;
}

/*
 * exit_rmtimeup()
 */
static void __exit exit_rmtimeup(void) {
  if (mod_register) {
    if (mod_unreg_security(MOD_REG_NAME, &rmtimeup_security_ops)) {
      printk(KERN_INFO "rmtimeup: failed to unregister "
                       "rmtimeup security module with primary "
                       "module.\n");
    }
  } else if (unregister_security(&rmtimeup_security_ops)) {
    printk(KERN_INFO "rmtimeup: failed to unregister "
                     "rmtimeup security module.\n");
  }
  printk(KERN_INFO "rmtimeup: unloaded\n");
}

security_initcall(init_rmtimeup);
module_exit(exit_rmtimeup);

#endif /* COMPILING */
