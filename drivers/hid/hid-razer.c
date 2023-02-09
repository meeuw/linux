// SPDX-License-Identifier: GPL-2.0+
/*
 *  HID driver for gaming keys on Razer Blackwidow gaming keyboards
 *  Macro Key Keycodes: M1 = 191, M2 = 192, M3 = 193, M4 = 194, M5 = 195
 *
 *  Copyright (c) 2021 Jelle van der Waa <jvanderwaa@redhat.com>
 */

#include <linux/device.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/usb.h>
#include <linux/wait.h>

#include "hid-ids.h"
#include "hid-razer.h"

#define map_key_clear(c) hid_map_usage_clear(hi, usage, bit, max, EV_KEY, (c))

static bool macro_key_remapping = 1;
module_param(macro_key_remapping, bool, 0644);
MODULE_PARM_DESC(macro_key_remapping, " on (Y) off (N)");

static unsigned char set_device_mode[] = {0x00, 0x04, 0x02, 0x00};

static int razer_input_mapping(struct hid_device *hdev,
		struct hid_input *hi, struct hid_field *field,
		struct hid_usage *usage, unsigned long **bit, int *max)
{

	if (!macro_key_remapping)
		return 0;

	if ((usage->hid & HID_UP_KEYBOARD) != HID_UP_KEYBOARD)
		return 0;

	switch (usage->hid & ~HID_UP_KEYBOARD) {
	case 0x68:
		map_key_clear(KEY_MACRO1);
		return 1;
	case 0x69:
		map_key_clear(KEY_MACRO2);
		return 1;
	case 0x6a:
		map_key_clear(KEY_MACRO3);
		return 1;
	case 0x6b:
		map_key_clear(KEY_MACRO4);
		return 1;
	case 0x6c:
		map_key_clear(KEY_MACRO5);
		return 1;
	}

	return 0;
}

static bool razer_check_control_interface(struct hid_device *hdev)
{
	int i;
	unsigned int hid;
	struct hid_report *report;
	struct hid_razer *hid_razer_drvdata;

	hid_razer_drvdata = hid_get_drvdata(hdev);

	list_for_each_entry(report, &hdev->report_enum[HID_FEATURE_REPORT].report_list, list) {
		for (i = 0; i < report->maxfield; i++) {
			hid = report->field[i]->usage->hid;

			if ((hid & HID_USAGE_PAGE) == HID_UP_MSVENDOR && (hid & HID_USAGE) == 0x2) {
				hid_razer_drvdata->report_count = report->field[i]->report_count;
				return true;
			}
		}
	}

	return false;
}

static int razer_control_message(struct hid_device *hdev, unsigned char data_len, unsigned char *data)
{
	struct hid_razer *hid_razer_drvdata;
	unsigned char* full_control_message;
	unsigned char crc = 0;
	unsigned int i;
	unsigned report_count;
	int ret;

	if (data_len < 2) {
		ret = -EINVAL;
		goto cleanup_and_exit;
	}

	hid_razer_drvdata = hid_get_drvdata(hdev);

	report_count = hid_razer_drvdata->report_count;

	if (report_count < 2) {
		ret = -EINVAL;
		goto cleanup_and_exit;
	}

	full_control_message = kzalloc(report_count + 1, GFP_KERNEL);

	if (full_control_message == NULL) {
		ret = -ENOMEM;
		goto cleanup_and_exit;
	}

	full_control_message[6] = data_len - 2;
	memcpy(full_control_message + 7, data, data_len);

	for(i = 2; i < report_count - 2; i++) {
		crc ^= full_control_message[i];
	}
	full_control_message[report_count - 1] = crc;

	ret = hid_hw_raw_request(hdev, 0, full_control_message, report_count + 1, HID_FEATURE_REPORT, HID_REQ_SET_REPORT);

	if (ret != report_count + 1) {
		ret = -EIO;
		goto cleanup_and_exit;
	}

cleanup_and_exit:
	kfree(full_control_message);

	return 0;
}


static int razer_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	int ret = 0;
	struct hid_razer *hid_razer_drvdata;

	hid_razer_drvdata = kzalloc(sizeof(struct hid_razer), GFP_KERNEL);
	if (hid_razer_drvdata == NULL) {
		return -ENOMEM;
	}
	hid_set_drvdata(hdev, hid_razer_drvdata);

	ret = hid_parse(hdev);

	if (ret)
		return ret;

	if (razer_check_control_interface(hdev)) {
		ret = razer_control_message(hdev, sizeof(set_device_mode), set_device_mode);
		if (ret) {
			hid_err(hdev, "failed to enable macro keys: %d\n", ret);
			return ret;
		}
	}

	return hid_hw_start(hdev, HID_CONNECT_DEFAULT);
}

static void razer_remove(struct hid_device *hdev)
{
	struct hid_razer *hid_razer_drvdata;

	hid_razer_drvdata = hid_get_drvdata(hdev);

	kfree(hid_razer_drvdata);
}

static const struct hid_device_id razer_devices[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_RAZER,
		USB_DEVICE_ID_RAZER_BLACKWIDOW) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_RAZER,
		USB_DEVICE_ID_RAZER_BLACKWIDOW_CLASSIC) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_RAZER,
		USB_DEVICE_ID_RAZER_BLACKWIDOW_ULTIMATE) },
	{ }
};
MODULE_DEVICE_TABLE(hid, razer_devices);

static struct hid_driver razer_driver = {
	.name = "razer",
	.id_table = razer_devices,
	.input_mapping = razer_input_mapping,
	.probe = razer_probe,
	.remove = razer_remove,
};
module_hid_driver(razer_driver);

MODULE_AUTHOR("Jelle van der Waa <jvanderwaa@redhat.com>");
MODULE_LICENSE("GPL");
