#ifndef _TGT_PRIV_H
#define _TGT_PRIV_H

struct tgt_target;

/* tgt core */
extern struct tgt_target *target_find(int tid);
extern int uspace_cmd_done(int tid, uint64_t cid, uint64_t devid,
			   int result, uint32_t len, uint64_t offset,
			   unsigned long addr,
			   uint8_t rw, uint8_t try_map);

/* netlink */
extern void tgt_nl_exit(void);
extern int tgt_nl_init(void);

/* Sysfs */
struct target_type_internal {
	int typeid;
	struct list_head list;
	struct tgt_target_template *tt;
	struct tgt_protocol *proto;
	struct class_device cdev;
};

extern int tgt_sysfs_init(void);
extern void tgt_sysfs_exit(void);
extern int tgt_sysfs_register_type(struct target_type_internal *ti);
extern void tgt_sysfs_unregister_type(struct target_type_internal *ti);
extern int tgt_sysfs_register_target(struct tgt_target *target);
extern void tgt_sysfs_unregister_target(struct tgt_target *target);

#endif
