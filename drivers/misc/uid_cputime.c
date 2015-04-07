/* drivers/misc/uid_cputime.c
 *
 * Copyright (C) 2014 - 2015 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

<<<<<<< HEAD
<<<<<<< HEAD
=======
#include <asm/thread_notify.h>

>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
<<<<<<< HEAD
<<<<<<< HEAD
#include <linux/profile.h>
=======
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
#include <linux/profile.h>
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define UID_HASH_BITS	10
DECLARE_HASHTABLE(hash_table, UID_HASH_BITS);

<<<<<<< HEAD
<<<<<<< HEAD
static DEFINE_MUTEX(uid_lock);
=======
static DEFINE_SPINLOCK(uid_lock);
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
static DEFINE_MUTEX(uid_lock);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
static struct proc_dir_entry *parent;

struct uid_entry {
	uid_t uid;
	cputime_t utime;
	cputime_t stime;
	cputime_t active_utime;
	cputime_t active_stime;
<<<<<<< HEAD
	unsigned long long active_power;
	unsigned long long power;
=======
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
	struct hlist_node hash;
};

static struct uid_entry *find_uid_entry(uid_t uid)
{
	struct uid_entry *uid_entry;
	struct hlist_node *node;

	hash_for_each_possible(hash_table, uid_entry, node, hash, uid) {
		if (uid_entry->uid == uid)
			return uid_entry;
	}
	return NULL;
}

static struct uid_entry *find_or_register_uid(uid_t uid)
{
	struct uid_entry *uid_entry;

	uid_entry = find_uid_entry(uid);
	if (uid_entry)
		return uid_entry;

	uid_entry = kzalloc(sizeof(struct uid_entry), GFP_ATOMIC);
	if (!uid_entry)
		return NULL;

	uid_entry->uid = uid;

	hash_add(hash_table, &uid_entry->hash, uid);

	return uid_entry;
}

static int uid_stat_show(struct seq_file *m, void *v)
{
	struct uid_entry *uid_entry;
<<<<<<< HEAD
	struct task_struct *task, *temp;
=======
	struct task_struct *task;
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
	struct hlist_node *node;
	cputime_t utime;
	cputime_t stime;
	unsigned long bkt;

<<<<<<< HEAD
<<<<<<< HEAD
	mutex_lock(&uid_lock);
=======
	spin_lock(&uid_lock);
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
	mutex_lock(&uid_lock);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.

	hash_for_each(hash_table, bkt, node, uid_entry, hash) {
		uid_entry->active_stime = 0;
		uid_entry->active_utime = 0;
<<<<<<< HEAD
		uid_entry->active_power = 0;
	}

	read_lock(&tasklist_lock);
	do_each_thread(temp, task) {
		uid_entry = find_or_register_uid(task_uid(task));
		if (!uid_entry) {
			read_unlock(&tasklist_lock);
			mutex_unlock(&uid_lock);
=======
	}

	read_lock(&tasklist_lock);
	for_each_process(task) {
		uid_entry = find_or_register_uid(task_uid(task));
		if (!uid_entry) {
			read_unlock(&tasklist_lock);
<<<<<<< HEAD
			spin_unlock(&uid_lock);
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
			mutex_unlock(&uid_lock);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
			pr_err("%s: failed to find the uid_entry for uid %d\n",
						__func__, task_uid(task));
			return -ENOMEM;
		}
<<<<<<< HEAD
		/* if this task is exiting, we have already accounted for the
		 * time and power. */
		if (task->cpu_power == ULLONG_MAX)
			continue;
		task_times(task, &utime, &stime);
		uid_entry->active_utime += utime;
		uid_entry->active_stime += stime;
		uid_entry->active_power += task->cpu_power;
	} while_each_thread(temp, task);
=======
		task_times(task, &utime, &stime);
		uid_entry->active_utime += utime;
		uid_entry->active_stime += stime;
	}
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
	read_unlock(&tasklist_lock);

	hash_for_each(hash_table, bkt, node, uid_entry, hash) {
		cputime_t total_utime = uid_entry->utime +
							uid_entry->active_utime;
		cputime_t total_stime = uid_entry->stime +
							uid_entry->active_stime;
<<<<<<< HEAD
		unsigned long long total_power = uid_entry->power +
							uid_entry->active_power;
		seq_printf(m, "%d: %llu %llu %llu\n", uid_entry->uid,
			(unsigned long long)jiffies_to_msecs(
				cputime_to_jiffies(total_utime)) * USEC_PER_MSEC,
			(unsigned long long)jiffies_to_msecs(
				cputime_to_jiffies(total_stime)) * USEC_PER_MSEC,
			total_power);
	}

	mutex_unlock(&uid_lock);
=======
		seq_printf(m, "%d: %u %u\n", uid_entry->uid,
						cputime_to_usecs(total_utime),
						cputime_to_usecs(total_stime));
	}

<<<<<<< HEAD
	spin_unlock(&uid_lock);
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
	mutex_unlock(&uid_lock);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
	return 0;
}

static int uid_stat_open(struct inode *inode, struct file *file)
{
	return single_open(file, uid_stat_show, PDE(inode)->data);
}

static const struct file_operations uid_stat_fops = {
	.open		= uid_stat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int uid_remove_open(struct inode *inode, struct file *file)
{
	return single_open(file, NULL, NULL);
}

static ssize_t uid_remove_write(struct file *file,
			const char __user *buffer, size_t count, loff_t *ppos)
{
	struct uid_entry *uid_entry;
	struct hlist_node *node, *tmp;
	char uids[128];
	char *start_uid, *end_uid = NULL;
	long int uid_start = 0, uid_end = 0;

	if (count >= sizeof(uids))
		count = sizeof(uids) - 1;

	if (copy_from_user(uids, buffer, count))
		return -EFAULT;

	uids[count] = '\0';
	end_uid = uids;
	start_uid = strsep(&end_uid, "-");

	if (!start_uid || !end_uid)
		return -EINVAL;

	if (kstrtol(start_uid, 10, &uid_start) != 0 ||
		kstrtol(end_uid, 10, &uid_end) != 0) {
		return -EINVAL;
	}

<<<<<<< HEAD
<<<<<<< HEAD
	mutex_lock(&uid_lock);
=======
	spin_lock(&uid_lock);
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
	mutex_lock(&uid_lock);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.

	for (; uid_start <= uid_end; uid_start++) {
		hash_for_each_possible_safe(hash_table, uid_entry, node, tmp,
							hash, uid_start) {
			hash_del(&uid_entry->hash);
			kfree(uid_entry);
		}
	}

<<<<<<< HEAD
<<<<<<< HEAD
	mutex_unlock(&uid_lock);
=======
	spin_unlock(&uid_lock);
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
	mutex_unlock(&uid_lock);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
	return count;
}

static const struct file_operations uid_remove_fops = {
	.open		= uid_remove_open,
	.release	= single_release,
	.write		= uid_remove_write,
};

<<<<<<< HEAD
<<<<<<< HEAD
static int process_notifier(struct notifier_block *self,
			unsigned long cmd, void *v)
{
	struct task_struct *task = v;
	struct uid_entry *uid_entry;
	cputime_t utime, stime;
	uid_t uid;

	if (!task)
		return NOTIFY_OK;

	mutex_lock(&uid_lock);
	uid = task_uid(task);
=======
static void uid_task_exit(struct task_struct *task)
=======
static int process_notifier(struct notifier_block *self,
			unsigned long cmd, void *v)
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
{
	struct task_struct *task = v;
	struct uid_entry *uid_entry;
	cputime_t utime, stime;
	uid_t uid;

	if (!task)
		return NOTIFY_OK;

<<<<<<< HEAD
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
	mutex_lock(&uid_lock);
	uid = task_uid(task);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
	uid_entry = find_or_register_uid(uid);
	if (!uid_entry) {
		pr_err("%s: failed to find uid %d\n", __func__, uid);
		goto exit;
	}

	task_times(task, &utime, &stime);
	uid_entry->utime += utime;
	uid_entry->stime += stime;
<<<<<<< HEAD
	uid_entry->power += task->cpu_power;
	task->cpu_power = ULLONG_MAX;

exit:
	mutex_unlock(&uid_lock);
	return NOTIFY_OK;
=======

exit:
<<<<<<< HEAD
	spin_unlock(&uid_lock);
}

static int process_notifier(struct notifier_block *self,
			unsigned long cmd, void *v)
{
	struct thread_info *thread = v;
	struct task_struct *task = v ? thread->task : NULL;

	if (!task)
		return NOTIFY_DONE;

	switch (cmd) {
	case THREAD_NOTIFY_EXIT:
		uid_task_exit(task);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
	mutex_unlock(&uid_lock);
	return NOTIFY_OK;
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.
}

static struct notifier_block process_notifier_block = {
	.notifier_call	= process_notifier,
};

static int __init proc_uid_cputime_init(void)
{
	hash_init(hash_table);

	parent = proc_mkdir("uid_cputime", NULL);
	if (!parent) {
		pr_err("%s: failed to create proc entry\n", __func__);
		return -ENOMEM;
	}

	proc_create_data("remove_uid_range", S_IWUGO, parent, &uid_remove_fops,
					NULL);

<<<<<<< HEAD
	proc_create_data("show_uid_stat", S_IRUGO, parent, &uid_stat_fops,
					NULL);

	profile_event_register(PROFILE_TASK_EXIT, &process_notifier_block);
=======
	proc_create_data("show_uid_stat", S_IWUGO, parent, &uid_stat_fops,
					NULL);

<<<<<<< HEAD
	thread_register_notifier(&process_notifier_block);
>>>>>>> 0559ddd... proc: uid: Adds accounting for the cputimes per uid.
=======
	profile_event_register(PROFILE_TASK_EXIT, &process_notifier_block);
>>>>>>> 6388df7... proc: uid: Changes the thread notifier to profile event notifier.

	return 0;
}

early_initcall(proc_uid_cputime_init);
