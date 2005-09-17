/*
 * Target framework core sysfs files
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */
#include <tgt_target.h>
#include <tgt_device.h>

/*
 * Target files
 */
#define tgt_target_show_fn(field, format_string)			\
static ssize_t								\
show_##field (struct class_device *cdev, char *buf)			\
{									\
	struct tgt_target *target = cdev_to_tgt_target(cdev);		\
	return snprintf (buf, 20, format_string, target->field);	\
}

#define tgt_target_rd_attr(field, format_string)		\
	tgt_target_show_fn(field, format_string)		\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_##field, NULL);

#define tgt_target_template_show_fn(field, format_string)		\
static ssize_t								\
show_##field (struct class_device *cdev, char *buf)			\
{									\
	struct tgt_target *target = cdev_to_tgt_target(cdev);		\
	return snprintf (buf, 20, format_string, target->tt->field);	\
}

#define tgt_target_template_rd_attr(field, format_string)		\
	tgt_target_template_show_fn(field, format_string)		\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_##field, NULL);

tgt_target_rd_attr(queued_cmnds, "%u\n");
tgt_target_template_rd_attr(name, "%s\n");
tgt_target_template_rd_attr(protocol, "%s\n");

static struct class_device_attribute *tgt_target_attrs[] = {
	&class_device_attr_queued_cmnds,
	&class_device_attr_name,
	&class_device_attr_protocol,
	NULL
};

static void tgt_target_class_release(struct class_device *cdev)
{
	struct tgt_target *target = cdev_to_tgt_target(cdev);
	kfree(target->tt_data);
	kfree(target);
}

static struct class tgt_target_class = {
	.name = "tgt_target",
	.release = tgt_target_class_release,
};

static struct class_device_attribute *class_attr_overridden(
				struct class_device_attribute **attrs,
				struct class_device_attribute *attr)
{
	int i;

	if (!attrs)
		return NULL;

	for (i = 0; attrs[i]; i++)
		if (!strcmp(attrs[i]->attr.name, attr->attr.name))
			return attrs[i];
	return NULL;
}

static int class_attr_add(struct class_device *classdev,
			  struct class_device_attribute *attr)
{
	struct class_device_attribute *base_attr;

	/*
	 * Spare the caller from having to copy things it's not interested in.
	*/
	base_attr = class_attr_overridden(tgt_target_attrs, attr);
	if (base_attr) {
		/* extend permissions */
		attr->attr.mode |= base_attr->attr.mode;

		/* override null show/store with default */
		if (!attr->show)
			attr->show = base_attr->show;
		if (!attr->store)
			attr->store = base_attr->store;
	}

	return class_device_create_file(classdev, attr);
}

int tgt_sysfs_register_target(struct tgt_target *target)
{
	struct class_device *cdev = &target->cdev;
	int err, i;

	cdev->class = &tgt_target_class;
	snprintf(cdev->class_id, BUS_ID_SIZE, "target%d", target->tid);

	err = class_device_register(cdev);
	if (err)
		return err;

	if (target->tt->target_attrs) {
		for (i = 0; target->tt->target_attrs[i]; i++) {
			err = class_attr_add(&target->cdev,
					     target->tt->target_attrs[i]);
                        if (err)
                                goto cleanup;
		}
	}

	for (i = 0; tgt_target_attrs[i]; i++) {
		if (!class_attr_overridden(target->tt->target_attrs,
					   tgt_target_attrs[i])) {
			err = class_device_create_file(&target->cdev,
						       tgt_target_attrs[i]);
			if (err)
				goto cleanup;
		}
	}

	return 0;

cleanup:
	class_device_unregister(cdev);
	return err;
}

void tgt_sysfs_unregister_target(struct tgt_target *target)
{
	class_device_unregister(&target->cdev);
}

/*
 * Device files
 */
#define tgt_device_show_fn(field, format_string)			\
static ssize_t								\
show_##field (struct class_device *cdev, char *buf)			\
{									\
	struct tgt_device *device = cdev_to_tgt_device(cdev);		\
	return sprintf(buf, format_string, device->field);	\
}

#define tgt_device_rd_attr(field, format_string)		\
	tgt_device_show_fn(field, format_string)		\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_##field, NULL);

tgt_device_rd_attr(path, "%s\n");
tgt_device_rd_attr(size, "%llu\n");

static struct class_device_attribute *tgt_device_attrs[] = {
	&class_device_attr_path,
	&class_device_attr_size,
	NULL,
};


static void tgt_device_class_release(struct class_device *cdev)
{
	struct tgt_device *device = cdev_to_tgt_device(cdev);
	struct tgt_target *target = device->target;

	class_device_put(&target->cdev);
	kfree(device->dt_data);
	kfree(device->path);
	kfree(device);
}

static struct class tgt_device_class = {
	.name = "tgt_device",
	.release = tgt_device_class_release,
};

int tgt_sysfs_register_device(struct tgt_device *device)
{
	struct tgt_target *target = device->target;
	struct class_device *cdev = &device->cdev;
	int err, i;

	cdev->class = &tgt_device_class;
	snprintf(cdev->class_id, BUS_ID_SIZE, "device%d:%llu",
		 target->tid, device->dev_id);
	err = class_device_register(cdev);
	if (err)
		return err;

	/*
	 * get handle to target so our parent is never released before
	 * us
	 */
	if (!class_device_get(&target->cdev))
		return -EINVAL;

	if (device->dt->device_attrs) {
		for (i = 0; device->dt->device_attrs[i]; i++) {
			err = class_attr_add(&device->cdev,
					     device->dt->device_attrs[i]);
                        if (err)
                                goto cleanup;
		}
	}

	for (i = 0; tgt_device_attrs[i]; i++) {
		if (!class_attr_overridden(device->dt->device_attrs,
					   tgt_device_attrs[i])) {
			err = class_device_create_file(&device->cdev,
						       tgt_device_attrs[i]);
			if (err)
				goto cleanup;
		}
	}

	return 0;

cleanup:
	class_device_put(&target->cdev);
	class_device_unregister(cdev);
	return err;

}

void tgt_sysfs_unregister_device(struct tgt_device *device)
{
	class_device_unregister(&device->cdev);
}

int tgt_sysfs_init(void)
{
	int err;

	err = class_register(&tgt_target_class);
	if (err)
		return err;

	err = class_register(&tgt_device_class);
	if (err)
		class_unregister(&tgt_target_class);
	return err;
}

void tgt_sysfs_exit(void)
{
	class_unregister(&tgt_target_class);
	class_unregister(&tgt_device_class);
}
