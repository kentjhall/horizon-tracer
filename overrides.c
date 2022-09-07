#define pr_fmt(fmt) "horizon override: " fmt

#include <linux/printk.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>
#include <linux/horizon/types.h>

#include "overrides.h"

#if 0 // EXAMPLE HORIZON SYSCALL OVERRIDE
#include <linux/horizon/result.h>
#include <linux/horizon/handle_table.h>

OVERRIDE1(send_sync_request, u32, session_handle)
{
	struct hzn_session_handler *handler;
	struct file *handler_file;
	long ret = REAL(send_sync_request);
	if (ret == HZN_RESULT_INVALID_HANDLE)
		return ret;

	handler_file = __hzn_handle_table_get(session_handle);
	handler = handler_file->private_data;
	pr_info("[0x%x] send_sync_request done, session_id=%lu, hzn_request_state=%d\n", current->hzn_thread_handle, handler->id, atomic_read(&current->hzn_request_state));
	fput(handler_file);
	return ret;
}
#endif
