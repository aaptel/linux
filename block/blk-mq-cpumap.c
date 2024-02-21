// SPDX-License-Identifier: GPL-2.0
/*
 * CPU <-> hardware queue mapping helpers
 *
 * Copyright (C) 2013-2014 Jens Axboe
 */
#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/group_cpus.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "blk.h"
#include "blk-mq.h"

enum map_mode {
	MAP_ROUND_ROBIN,
	MAP_NUMA_GROUP,
	MAP_MODE_COUNT,
};

static struct { const char *name; unsigned mode; } g_map_mode_names[] = {
	{"round-robin", MAP_ROUND_ROBIN},
	{"numa-group", MAP_NUMA_GROUP},
};

static enum map_mode g_map_mode = -1;

static int map_mode_show(struct seq_file *m, void *data) {
	seq_printf(m, "%s\n", g_map_mode_names[g_map_mode].name);
	return 0;
}

static int map_mode_open(struct inode *inode, struct file *file) {
	return single_open(file, map_mode_show, NULL);
}

static ssize_t map_mode_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos) {
	int i;
	char input[32] = {0};

	if (count >= sizeof(input) || count <= 0)
		return -EINVAL;

	if (copy_from_user(input, buffer, count))
		return -EFAULT;
	
	for (i = 0; i < MAP_MODE_COUNT; i++) {
		const char *name = g_map_mode_names[i].name;
		size_t len = strlen(name);
		unsigned mode = g_map_mode_names[i].mode;

		if (count >= len && strncmp(input, name, len) == 0) {
			g_map_mode = mode;
			return count;
		}
	}

	return -EINVAL;
}

static const struct proc_ops map_mode_fops = {
	.proc_open       = map_mode_open,
	.proc_read       = seq_read,
	.proc_lseek      = seq_lseek,
	.proc_write      = map_mode_write,
	.proc_release    = single_release,
};

static void map_mode_init(void) {
	if (g_map_mode == -1) {
		proc_create("blk_cpu_map_mode", 0666, NULL, &map_mode_fops);
		g_map_mode = 0;
	}
}


static int queue_index(struct blk_mq_queue_map *qmap,
		       unsigned int nr_queues, const int q)
{
	return qmap->queue_offset + (q % nr_queues);
}

static int get_first_sibling(unsigned int cpu)
{
	unsigned int ret;

	ret = cpumask_first(topology_sibling_cpumask(cpu));
	if (ret < nr_cpu_ids)
		return ret;

	return cpu;
}

static void blk_mq_map_queues_numa(struct blk_mq_queue_map *qmap)
{
        const struct cpumask *masks;
        unsigned int queue, cpu;

        masks = group_cpus_evenly(qmap->nr_queues);
        if (!masks) {
                for_each_possible_cpu(cpu)
                        qmap->mq_map[cpu] = qmap->queue_offset;
                return;
        }

        for (queue = 0; queue < qmap->nr_queues; queue++) {
                for_each_cpu(cpu, &masks[queue])
                        qmap->mq_map[cpu] = qmap->queue_offset + queue;
        }
        kfree(masks);
}

static void blk_mq_map_queues_round_robin(struct blk_mq_queue_map *qmap)
{
	unsigned int *map = qmap->mq_map;
	unsigned int nr_queues = qmap->nr_queues;
	unsigned int cpu, first_sibling, q = 0;

	for_each_possible_cpu(cpu)
		map[cpu] = -1;

	/*
	 * Spread queues among present CPUs first for minimizing
	 * count of dead queues which are mapped by all un-present CPUs
	 */
	for_each_present_cpu(cpu) {
		if (q >= nr_queues)
			break;
		map[cpu] = queue_index(qmap, nr_queues, q++);
	}

	for_each_possible_cpu(cpu) {
		if (map[cpu] != -1)
			continue;
		/*
		 * First do sequential mapping between CPUs and queues.
		 * In case we still have CPUs to map, and we have some number of
		 * threads per cores then map sibling threads to the same queue
		 * for performance optimizations.
		 */
		if (q < nr_queues) {
			map[cpu] = queue_index(qmap, nr_queues, q++);
		} else {
			first_sibling = get_first_sibling(cpu);
			if (first_sibling == cpu)
				map[cpu] = queue_index(qmap, nr_queues, q++);
			else
				map[cpu] = map[first_sibling];
		}
	}
}

void blk_mq_map_queues(struct blk_mq_queue_map *qmap)
{
	map_mode_init();

	if (g_map_mode == MAP_ROUND_ROBIN)
		blk_mq_map_queues_round_robin(qmap);
	else
		blk_mq_map_queues_numa(qmap);
}
EXPORT_SYMBOL_GPL(blk_mq_map_queues);

/**
 * blk_mq_hw_queue_to_node - Look up the memory node for a hardware queue index
 * @qmap: CPU to hardware queue map.
 * @index: hardware queue index.
 *
 * We have no quick way of doing reverse lookups. This is only used at
 * queue init time, so runtime isn't important.
 */
int blk_mq_hw_queue_to_node(struct blk_mq_queue_map *qmap, unsigned int index)
{
	int i;

	for_each_possible_cpu(i) {
		if (index == qmap->mq_map[i])
			return cpu_to_node(i);
	}

	return NUMA_NO_NODE;
}
