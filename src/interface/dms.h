/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * DMS is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * dms.h
 *
 *
 * IDENTIFICATION
 *    src/interface/dms.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_H__
#define __DMS_H__

#include "dms_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#  if defined(DSS_EXPORTS)
#    define DMS_DECLARE      __declspec(dllexport)
#  elif defined(DSS_IMPORTS)
#    define DMS_DECLARE      __declspec(dllimport)
#  else
#    define DMS_DECLARE
#  endif
#else
#define DMS_DECLARE __attribute__ ((visibility ("default")))
#endif

/*
* @brief DMS init
* @[in]param profile -  config value
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_init(dms_profile_t *dms_profile);

/*
* @brief DMS init logger
 * @[in] param param_def - logger parameter 
 * @return DMS_SUCCESS - success; otherwise: failed
*/
DMS_DECLARE int dms_init_logger(logger_param_t *param_def);

/*
* @brief DMS refresh logger configure
 * @[in] log_field -  logger configure string.
 * @[in] value -  logger configure value.
 * @return void 
*/
DMS_DECLARE void dms_refresh_logger(char *log_field, unsigned long long *value);

/*
* @brief DMS get error msg and error code
 * @[out]param errcode -  get dms error code.
 * @[out]param errmsg -  get dms error msg.
 * @return
*/
DMS_DECLARE void dms_get_error(int *errcode, const char **errmsg);

/*
* @brief DMS sets thread memctx for mes
* @[in]param profile -  config value
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_register_thread_init(dms_thread_init_t thrd_init);

/*
* @brief DMS sets deinit function for thread
* @[in]param thrd_deinit -  function for deinit
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_register_thread_deinit(dms_thread_deinit_t thrd_deinit);

/*
* @brief DMS pre uninit, only uninit reform context
* @return
*/
DMS_DECLARE void dms_pre_uninit(void);

/*
 * @brief DMS uninit
 * @return
 */
DMS_DECLARE void dms_uninit(void);

/*
 * @brief get page data.
 * @[in]param dms_ctx -  Obtains the context information required by the page.
 * @[in&out]param ctrl -  DMS buffer ctrl of the page.
 * @[in]param mode -  DMS lock mod.
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_request_page(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t mode);

/*
 * @brief sleep if dms_request_page return error
 */
DMS_DECLARE void dms_request_page_wait(void);

/*
* @brief forward to specified node to construct heap CR page.
* @[in]param dms_ctx -  Obtains the context information required by the page.
* @[in&out]param dms_cr -  Properties required to construct a consistent page.
* @[in]param dst_inst_id - the instance id that continues to construct heap CR page.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_forward_heap_cr_page_request(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id);

/*
* @brief forward to specified node to construct btree CR page.
* @[in]param dms_ctx -  Obtains the context information required by the page.
* @[in&out]param dms_cr -  Properties required to construct a consistent page.
* @[in]param dst_inst_id - the instance id that continues to construct btree CR page.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_forward_btree_cr_page_request(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id);

/*
* @brief request master or owner heap consistent-read page.
* @[in]param dms_ctx -  Obtains the context information required by the page.
* @[in&out]param dms_cr -  Properties required to construct a consistent page.
* @[in]param dst_inst_id -  master or owner id.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_request_heap_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id);

/*
* @brief get the instance id to construct consistency read page .
* @[in]param dms_ctx -  Obtains the context information required by the page.
* @[out]param dst_inst_id -  Notify dst_inst_id(instance id) to construct a consistent page.
* @[in&out]param cr_phase -  the phase of the construct cr page.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_cr_check_master(dms_context_t *dms_ctx, unsigned int *dst_inst_id, dms_cr_phase_t *cr_phase);

/*
 * @brief check current row is the row we are reading or not.
 * @[in]param dms_ctx -  Obtains the context information required by the page.
 * @[in]param dms_cr -  Properties required to construct a consistent page.
 * @[in]param dst_inst_id -  Notify dst_inst_id(instance id) to check visible.
 * @[out]param is_empty_itl - is_empty_itl(1):empty, or not
 * @[out]param is_found -  is_found(1):visible, is_found(0):invisible.
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_check_current_visible(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id,
    unsigned char *is_empty_itl, unsigned char *is_found);

/*
* @brief try ask master for page owner id.
* @[in]param dms_ctx -  Obtains the context information required by the page.
* @[in]param dms_cr -  Properties required to construct a consistent page.
* @[in]param req_mode -  lock mode.
* @[out]param owner_id -  page owner id.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_try_ask_master_for_page_owner_id(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl,
    dms_lock_mode_t req_mode, unsigned char *owner_id);

/*
* @brief init distributed pl spin lock.
* @param lock - distributed resource lock identifier.
* @param type - distributed resource type.
* @param oid - resource object id.
* @param uid - resource user id.
* @return
*/
DMS_DECLARE void dms_init_pl_spinlock(dms_drlock_t *lock, dms_dr_type_t type, unsigned long long oid,
    unsigned short uid);

/*
* @brief init distributed spin lock.
* @param lock - distributed resource lock identifier.
* @param type - distributed resource type.
* @param oid - resource object id.
* @param uid - resource user id.
* @return
*/
DMS_DECLARE void dms_init_spinlock(dms_drlock_t *lock, dms_dr_type_t type, unsigned int oid,
    unsigned short uid);

/*
* @brief init distributed spin lock.
* @param lock - distributed resource lock identifier.
* @param type - distributed resource type.
* @param oid - resource object id.
* @param uid - resource user id.
* @param idx - resource index id.
* @param parent_part - resource parent partition id.
* @param part - resource partition id.
* @return
*/
DMS_DECLARE void dms_init_spinlock2(dms_drlock_t *lock, dms_dr_type_t type, unsigned int oid, unsigned short uid,
    unsigned int idx, unsigned int parent_part, unsigned int part);

/*
* @brief distributed spin lock acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlock - distributed resource lock identifier.
* @return
*/
DMS_DECLARE void dms_spin_lock(dms_context_t *dms_ctx, dms_drlock_t *dlock);

/*
* @brief distributed spin lock release method.
* @param dms_ctx - dms_context_t structure.
* @param dlock - distributed resource lock identifier.
* @return
*/
DMS_DECLARE void dms_spin_unlock(dms_context_t *dms_ctx, dms_drlock_t *dlock);

/*
* @brief distributed shared spin lock acquire method.
* @function intra-node shared and inter-node exclusive
* @param dms_ctx - dms_context_t structure.
* @param dlock - distributed resource lock identifier.
* @return
*/
DMS_DECLARE void dms_spin_lock_innode_s(dms_context_t *dms_ctx, dms_drlock_t *dlock);

/*
* @brief distributed shared spin lock release method.
* @function intra-node shared and inter-node exclusive
* @param dms_ctx - dms_context_t structure.
* @param dlock - distributed resource lock identifier.
* @return
*/
DMS_DECLARE void dms_spin_unlock_innode_s(dms_context_t *dms_ctx, dms_drlock_t *dlock);

/*
* @brief distributed spin lock try to acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlock - distributed resource lock identifier.
* @return CM_TRUE acquire success; CM_FALSE acquire fail.
*/
DMS_DECLARE unsigned char dms_spin_try_lock(dms_context_t *dms_ctx, dms_drlock_t *dlock);

/*
* @brief distributed spin lock timeout acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlock - distributed resource lock identifier.
* @param timeout_ticks - timeout ticks.
* @return CM_TRUE acquire success; CM_FALSE acquire fail.
*/
DMS_DECLARE unsigned char dms_spin_timed_lock(dms_context_t *dms_ctx, dms_drlock_t *dlock, unsigned int timeout_ticks);

/*
* @brief init distributed pl latch.
* @param dlatch - distributed resource lock identifier.
* @param type - distributed resource type.
* @param oid - resource object id.
* @param uid - resource user id.
* @return
*/
DMS_DECLARE void dms_init_pl_latch(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned long long oid,
    unsigned short uid);

/*
* @brief init distributed latch.
* @param dlatch - distributed resource lock identifier.
* @param type - distributed resource type.
* @param oid - resource object id.
* @param uid - resource user id.
* @return
*/
DMS_DECLARE void dms_init_latch(dms_drlatch_t* dlatch, dms_dr_type_t type, unsigned int oid,
    unsigned short uid);

/*
* @brief init distributed latch.
* @param dlatch - distributed resource lock identifier.
* @param type - distributed resource type.
* @param oid - resource object id.
* @param uid - resource user id.
* @param idx - resource index id.
* @param parent_part - resource parent partition id.
* @param part - resource partition id.
* @return
*/
DMS_DECLARE void dms_init_latch2(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned int oid, unsigned short uid,
    unsigned int idx, unsigned int parent_part, unsigned int part);

/*
* @brief distributed latch shared acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @param sid - session id.
* @param is_force - whether force to shared mode when contention with exclusive mode.
* @return
*/
DMS_DECLARE void dms_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned char is_force);

/*
* @brief distributed latch shared acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @return CM_TRUE acquire success; CM_FALSE acquire failed.
*/
DMS_DECLARE unsigned char dms_try_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch);

/*
* @brief distributed latch shared acquire timeout method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @param wait_ticks - timeout ticks.
* @param is_force - whether force to shared mode when contention with exclusive mode.
* @return CM_TRUE acquire success; CM_FALSE acquire failed.
*/
DMS_DECLARE unsigned char dms_latch_timed_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch,
    unsigned int wait_ticks, unsigned char is_force);

/*
* @brief distributed latch exclusive acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @param sid - session id.
* @return
*/
DMS_DECLARE void dms_latch_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch);

/*
* @brief distributed latch exclusive acquire timeout method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @param wait_ticks - timeout ticks.
* @param is_force - whether force to shared mode when contention with exclusive mode.
* @return CM_TRUE acquire success; CM_FALSE acquire failed.
*/
DMS_DECLARE unsigned char dms_latch_timed_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks);

/*
* @brief distributed table shared latch acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @return CM_TRUE acquire success; CM_FALSE acquire failed.
*/
DMS_DECLARE unsigned char dms_try_tlatch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch);

/*
* @brief distributed table shared latch acquire timeout method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @param wait_ticks - timeout ticks.
* @return CM_TRUE acquire success; CM_FALSE acquire failed.
*/
DMS_DECLARE unsigned char dms_tlatch_timed_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks);

/*
* @brief distributed table exclusive latch acquire timeout method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @param wait_ticks - timeout ticks.
* @return CM_TRUE acquire success; CM_FALSE acquire failed.
*/
DMS_DECLARE unsigned char dms_tlatch_timed_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks);

/*
* @brief distributed table exclusive latch acquire method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @return CM_TRUE acquire success; CM_FALSE acquire failed.
*/
DMS_DECLARE unsigned char dms_tlatch_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch);

/*
* @brief distributed latch release method.
* @param dms_ctx - dms_context_t structure.
* @param dlatch - distributed resource lock identifier.
* @return
*/
DMS_DECLARE void dms_unlatch(dms_context_t *dms_ctx, dms_drlatch_t *dlatch);

/*
* @brief broadcast message to other instances.
* @param dms_ctx - dms_context_t structure.
* @param data - message data.
* @param len - message length.
* @param handle_recv_msg - handle_recv_msg.
* @param timeout - wait response msg in timeout
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_broadcast_msg(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout);

/*
* @brief broadcast message to other instances.
* @param dms_ctx - dms_context_t structure.
* @param data - message data.
* @param len - message length.
* @param handle_recv_msg - handle_recv_msg.
* @param timeout - wait response msg in timeout
* @param sope - broadcast scope
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_broadcast_msg_with_scope(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout, dms_broadcast_scope_e scope);

/*
* @brief broadcast message to other instances.
* @param dms_ctx - dms_context_t structure.
* @param data - message data.
* @param len - message length.
* @param timeout - wait response msg in timeout
* @param output - output
* @param output_len - output length
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_smon_broadcast_msg(dms_context_t *dms_ctx, char *data, unsigned int len, unsigned int timeout,
    char *output, unsigned int *output_len);

/*
* @brief broadcast ddl sync message to other instances.
* @param dms_ctx - dms_context_t structure.
* @param data - message data.
* @param len - message length.
* @param handle_recv_msg - handle_recv_msg.
* @param timeout - wait response msg in timeout
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_broadcast_ddl_sync_msg(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout, dms_broadcast_scope_e scope, unsigned char check_session_kill);

/*
* @brief broadcast scn to other instances when commit transaction.
* @param dms_ctx - dms_context_t structure.
* @param commit_scn - commit scn of transaction
* @param min_scn - min scn of current instance
* @param success_inst - instances in which the broadcast message was successfully sent
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_send_boc(dms_context_t *dms_ctx, unsigned long long commit_scn, unsigned long long min_scn,
    unsigned long long *success_inst, unsigned long long *ruid);

/*
* @brief wait boc ack from other instances.
* @param ruid - ruid returned from message sending api.
* @param timeout - wait response msg in timeout
* @param success_inst - instances in which the broadcast message was successfully sent
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_wait_boc(unsigned long long ruid, unsigned int timeout, unsigned long long success_inst);

/*
* @brief get openGauss multixactid's update xid.
* @[in]param dms_ctx -  Obtains the context information required by txn info.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_request_opengauss_update_xid(dms_context_t *dms_ctx,
    unsigned short t_infomask, unsigned short t_infomask2, unsigned long long *uxid);

/*
* @brief get xid's openGauss txn info.
* @[in]param dms_ctx -  Obtains the context information required by txn info.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_request_opengauss_xid_csn(dms_context_t *dms_ctx, dms_opengauss_xid_csn_t *dms_txn_info,
    dms_opengauss_csn_result_t *xid_csn_result);

/*
* @brief get xid's openGauss txn status.
* @[in]param dms_ctx -  Obtains the context information required by txn status.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_request_opengauss_txn_status(dms_context_t *dms_ctx, unsigned char request, unsigned char *result);

/*
* @brief get xid's txn info.
* @[in]param dms_ctx -  Obtains the context information required by txn info.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_request_txn_info(dms_context_t *dms_ctx, dms_txn_info_t *dms_txn_info);

/*
 * @brief get openGauss snapshot data.
 * @[in] dms_ctx - Obtains the context information required by txn info
 * @return DMS_SUCCESS - success; otherwise failed
 */
DMS_DECLARE int dms_request_opengauss_txn_snapshot(dms_context_t *dms_ctx,
    dms_opengauss_txn_snapshot_t *dms_txn_snapshot);

/*
 * @brief get openGauss transaction id and command id of primary for standby write feature.
 * @[in] dms_ctx - Obtains the context information required by txn info
 * @return DMS_SUCCESS - success; otherwise failed
 */
DMS_DECLARE int dms_request_opengauss_txn_of_master(dms_context_t *dms_ctx,
    dms_opengauss_txn_sw_info_t *dms_txn_swinfo);

/*
 * @brief get openGauss page buffer status.
 * @[in] dms_ctx - Obtains the context information required by page status
 * @return DMS_SUCCESS - success; otherwise failed
 */
DMS_DECLARE int dms_request_opengauss_page_status(dms_context_t *dms_ctx,
    unsigned int page, int page_num, unsigned long int *page_map, int *bit_count);

/*
 * @brief get openGauss buffer lock mode and lock the buffer.
 * @[in] dms_ctx - Obtains the context information required by txn info
 * @return DMS_SUCCESS - success; otherwise failed
 */
DMS_DECLARE int dms_request_opengauss_lock_buffer(dms_context_t *dms_ctx,
    int buffer, unsigned char mode, unsigned char *lw_lock_mode);

/*
* @brief openGauss broadcast DDLLockAccquire and DDLLockRelease message to other instances.
* @param dms_ctx - dms_context_t structure.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_broadcast_opengauss_ddllock(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout, unsigned char resend_after_reform);

/*
 * @brief get xmap's txn snapshot.
 * @[in] dms_ctx - Obtains the context information required by txn info
 * @return DMS_SUCCESS - success; otherwise failed
 */
DMS_DECLARE int dms_request_txn_snapshot(dms_context_t *dms_ctx, dms_txn_snapshot_t *dms_txn_snapshot);

/*
 * @brief query xid's transaction wait status
 * @[in] dms_ctx - xid_ctx has stored the xid information
 * @return success will return DMS_SUCCESS, status will be DMS_REMOTE_TXN_WAIT or DMS_REMOTE_TXN_END
 */
DMS_DECLARE int dms_request_txn_cond_status(dms_context_t *dms_ctx, int *status);

/*
 * @brief wait until timeout or the remote transaction has be finished.
 * @[in] dms_ctx - xid_ctx has stored the xid information
 * @return GS_TRUE: the remote transaction has been finished.
 * GS_FALSE: timeout or interrupted.
 */
DMS_DECLARE unsigned char dms_wait_txn_cond(dms_context_t *dms_ctx);

/*
 * @brief recycle local instance transaction wait condition variable
 * @[in] dms_ctx - xid_ctx has stored the xid information
 * @return void
 */
DMS_DECLARE void dms_recycle_txn_cond(dms_context_t *dms_ctx);

/*
 * @brief awake all waited transaction in other instances and release the txn resource
 * @[in] dms_ctx - xid_ctx has stored the xid information and scn.
 * @return void
 */
DMS_DECLARE void dms_release_txn_cond(dms_context_t *dms_ctx);

/*
 * @brief get inst_id's deposit instance id
 * @[in] inst_id - the instance id which will be deposited
 * @return unsigned char - the deposited id
 */
DMS_DECLARE unsigned char dms_get_deposit_id(unsigned char inst_id);

/*
 * @brief get dv_drc_buf_info
 * @[in] index - index in pool
 * @[in] res_buf_info - record res buffer info
 * @[in] drc_type - the type of drc, page or lock
 * @return unsigned char - the deposited id
 */
DMS_DECLARE void dms_get_buf_res(unsigned long long *index, dv_drc_buf_info *res_buf_info, int drc_type);

/*
 * @brief release owner
 * @[in]param dms_ctx -  Obtains the context information.
 * @[in]param ctrl -  Obtains the context information.
 * @[out]param released - CM_TRUE or CM_FALSE
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_release_owner(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, unsigned char *released);

/*
 * @brief release owner
 * @[in]param dms_ctx -  Obtains the context information.
 * @[out]param released - CM_TRUE or CM_FALSE
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_can_release_owner(dms_context_t *dms_ctx, unsigned char *released);

/*
* @brief wait reform done
* @return - if reform done, then return
*/
DMS_DECLARE int dms_wait_reform(unsigned int *has_offline);

/*
* @brief checkpoint EDP
* @[in]param dms_ctx -  Obtains the context information.
* @[in]param pages - EDP array.
* @[out]param count - EDP count.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_ckpt_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, unsigned int count);

/*
* @brief clean EDP
* @[in]param dms_ctx -  Obtains the context information.
* @[in]param pages - EDP array.
* @[out]param count - EDP count.
* @return DMS_SUCCESS - success;otherwise: failed
*/
DMS_DECLARE int dms_clean_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, unsigned int count);

/*
 * @brief get min scn
 * @[in]param min_scn - current min scn .
 * @return Minimum scn of the cluster
 */
DMS_DECLARE unsigned long long dms_get_min_scn(unsigned long long min_scn);

/*
 * @brief set min scn
 * @[in]param min_scn - cluster min scn .
 * @return
 */
DMS_DECLARE void dms_set_min_scn(unsigned char inst_id, unsigned long long min_scn);

/*
 * @brief retrieve dms statistics of waiting events
 * @[in]param the type of waiting event
 * @[out]the count of the happenings of specified waiting event
 * @[out]the total cost time of specified waiting event
 * @return
 */
DMS_DECLARE void dms_get_event(dms_wait_event_t event_type, unsigned long long *event_cnt,
    unsigned long long *event_time);

/*
 * @brief retrieve dms critical performance statistics
 * @[in]param the type of statistic
 * @return the total cost time of specified waiting event
 */
DMS_DECLARE unsigned long long dms_get_stat(dms_sysstat_t stat_type);

/*
 * @brief reset dms critical statistics
 * @[in]param the type of statistic
 * @return
 */
DMS_DECLARE void dms_reset_stat(void);

/*
 * @brief The smon thread obtains cluster transactions.
 * @[in]param dms_ctx - dms_context_t structure.
 * @[in]param dst_inst - Target Instance
 * @[in]param rmid - rmid
 * @[in]param type - type
 * @[out]param rsp_content - rsp_content
 * @[in]param rsp_size - rsp_size
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_smon_request_ss_lock_msg(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short rmid,
    dms_smon_req_type_t type, char *rsp_content, unsigned int rsp_size);

/*
 * @brief SQL statement for obtaining deadlocks by the smon thread
 * @[in]param dms_ctx - dms_context_t structure.
 * @[in]param dst_inst - Target Instance
 * @[in]param sid - session id
 * @[out]param sql_str - sql_str
 * @[in]param sql_str_len - sql_str length
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_smon_request_sql_from_sid(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short sid,
    char *sql_str, unsigned int sql_str_len);

/*
 * @brief the smon thread get itl lock msg
 * @[in]param dms_ctx - dms_context_t structure.
 * @[in]param dst_inst - Target Instance
 * @[in]param xid - xid
 * @[out]param ilock - ilock
 * @[in]param ilock - ilock length
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_smon_request_itl_lock_msg(dms_context_t *dms_ctx, unsigned char dst_inst, char xid[DMS_XID_SIZE],
    char *ilock, unsigned int ilock_len);

/*
 * @brief the smon thread get table lock msg by rm
 * @[in]param dms_ctx - dms_context_t structure.
 * @[in]param dst_inst - Target Instance
 * @[in]param sid - sid
 * @[in]param rmid - rmid
 * @[in]param type - type
 * @[out]param tlock - tlock
 * @[in]param tlock_len - tlock length
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_smon_req_tlock_by_rm(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short sid,
    unsigned short rmid, dms_smon_req_rm_type_t type, char *tlock, unsigned int tlock_len);

/*
 * @brief rebuild table lock when node abort.
 * @[in]param dms_ctx -  Obtains the context information required by the page.
 * @[in]param lock_info -  table lock information.
 * @[in]param thread_index - thread index
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_tlock_rebuild_drc_parallel(dms_context_t *dms_ctx, dms_tlock_info_t *lock_info,
    unsigned char thread_index);

/*

 * @brief the smon thread get tlock by table id
 * @[in]param dms_ctx - dms_context_t structure.
 * @[in]param data - tlock
 * @[in]param len - length
 * @[in]param inst_id - instance id
 * @[out]param stack - stack
 * @[in]param w_marks - w_marks
 * @[out]param valid_cnt - valid_cnt
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_smon_req_tlock_by_tid(dms_context_t *dms_ctx, void *data, unsigned int len, unsigned int inst_id,
    char *stack, char *w_marks, unsigned int *valid_cnt);

/*
 * @brief rebuild drc when node abort.
 * @[in]param dms_ctx -  Obtains the context information required by the page.
 * @[in]param ctrl -  DMS buffer ctrl of the page.
 * @[in]param lsn -  page lsn.
 * @[in]param is_dirty -  page is dirty or not.
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_buf_res_rebuild_drc_parallel(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    unsigned char thread_index);

DMS_DECLARE int dms_reform_validate_page_parallel(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    unsigned char thread_index);

/*
 * @brief validate table lock during reform.
 * @[in]param dms_ctx -  Obtains the context information required by the page.
 * @[in]param lock_info -  table lock information.
 * @[in]param thread_index - thread index
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_reform_validate_tlock_parallel(dms_context_t *dms_ctx, dms_tlock_info_t *lock_info,
    unsigned char thread_index);

/*
 * @brief check if session is recovery session or not.
 * @[in]param sid - session id.
 * @return 1 - if session is recovery session;otherwise: 0
 */
DMS_DECLARE int dms_is_recovery_session(unsigned int sid);

/*
 * @brief get page master
 * @[in]param pageid - page id
 * @[out]param master_id - master id
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int drc_get_page_master_id(char pageid[DMS_PAGEID_SIZE], unsigned char *master_id);

/*
 * @brief register ssl decrypt func
 * @[in] cb_func -ssl decrypt func.
 * @* @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_register_ssl_decrypt_pwd(dms_decrypt_pwd_t cb_func);

/*
 * @brief set ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_CIPHERTEXT、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[in] param value--ssl cert or ssl key
 * @* @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_set_ssl_param(const char* param_name, const char* param_value);

/*
 * @brief get ssl relevant param
 * @[in] param name(SSL_CA、SSL_KEY、SSL_PWD_CIPHERTEXT、SSL_PWD_PLAINTEXT、SSL_CERT).
 * @[out]param value--ssl cert or ssl key
 * @[out]size--ssl cert or ssl key size
 * @* @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_get_ssl_param(const char *param_name, char *param_value, unsigned int size);

/*
 * @brief check page if need skip or not while recovery
 * @[in] pageid
 * @[out]skip--need skip or not
 * @* @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_recovery_page_need_skip(char pageid[DMS_PAGEID_SIZE], unsigned char *skip, unsigned int alloc,
    unsigned long long group_lsn);

/*
 * @brief unregister lsn when analyse redo
 * @[in] pageid
 * @[in] group_lsn
 * @* @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_recovery_unregister_group_lsn(char pageid[DMS_PAGEID_SIZE], unsigned long long group_lsn);

/*
 * @brief check reform if failed
 * @* @return TRUE - reform failed; FALSE - reform normal
 */
DMS_DECLARE int dms_reform_failed(void);

/*
 * @brief request primary for switchover
 * @[in] sess_id
 * @* @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_switchover(unsigned int sess_id);
/*
 * @brief check drc if accessible or not
 * @* @return TRUE - accessible; FALSE - inaccessible
 */
DMS_DECLARE int dms_drc_accessible(unsigned char res_type);

/*
 * @brief get dms version
 * @* @return version
 */
DMS_DECLARE int dms_get_version(void);

/*
 * @brief check if reform is running
 * @* @return true&false
 */
DMS_DECLARE int dms_reform_in_process(void);

/*
 * @brief show dms version
 * @* @return dms version
 */
DMS_DECLARE void dms_show_version(char *version);

/*
 * @brief means current node think this round reform failed
 * @ different form dms_reform_failed which used in reform phase，such recovery phase
 * @ this method used in this Scenario
 *      Database need to wait reform finish
 * @* @return TRUE - reform failed; FALSE - reform normal
 */
DMS_DECLARE int dms_reform_last_failed(void);

DMS_DECLARE int dms_wait_reform_phase(unsigned char reform_phase);
DMS_DECLARE int dms_wait_reform_finish(void);
DMS_DECLARE void dms_set_reform_continue(void);

DMS_DECLARE int dms_is_reformer(void);
DMS_DECLARE int dms_is_share_reformer(void);

DMS_DECLARE void dms_file_enter(void);
DMS_DECLARE void dms_file_leave(void);

DMS_DECLARE int dms_send_bcast(dms_context_t *dms_ctx, void *data, unsigned int len,
    unsigned long long *success_inst, unsigned long long *ruid);
DMS_DECLARE int dms_wait_bcast(unsigned long long ruid, unsigned int inst_id, unsigned int timeout,
    unsigned long long *success_inst);
/*
 * @brief thorough check for DRC and bufferpool buffer befor reform ends
 * @ PANIC if any of version, pageid, lockmode and need_flush is unmatched.
 */
DMS_DECLARE void dms_validate_drc(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl,
    unsigned long long lsn, unsigned char is_dirty);

/*
* @brief set log level
* @[in]param log_level -  db log level.
*/
DMS_DECLARE void dms_set_log_level(unsigned int log_level);

/*
 * @brief get latch owner id
 * @[in]param dms_ctx - dms_context_t structure.
 * @[in]param dlatch - dms_drlatch_t structure.
 * @[out]param owner_id - owner id.
 * @return DMS_SUCCESS - success;otherwise: failed.
 */
DMS_DECLARE int dms_get_latch_owner_id(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned char *owner_id);

/*
 * @brief request primary node redo page in on-demand recovery, only for openGauss
 * @[in]param dms_ctx - obtains the context information required by the page.
 * @[in]param block_key - page information.
 * @[in]param key_len - len of page information.
 * @[out]redo_status - redo result.
 * @return DMS_SUCCESS - success;otherwise: failed.
 */
DMS_DECLARE int dms_reform_req_opengauss_ondemand_redo_buffer(dms_context_t *dms_ctx, void *block_key,
    unsigned int key_len, int *redo_status);

DMS_DECLARE int dms_info(char *buf, unsigned int len, unsigned int curr);

DMS_DECLARE int dms_reform_res_need_rebuild(char *res, unsigned char res_type, unsigned int *need_rebuild);

DMS_DECLARE unsigned int dms_get_mes_max_watting_rooms(void);

DMS_DECLARE void dms_reform_cache_curr_point(unsigned int node_id, void *curr_point);

/*
 * @brief send oldest_xmin
 * @[in]param dms_ctx -  context information.
 * @[in]param oldest_xmin -  oldest xmin during snapshot in node 
 * @[in]param dest_id -  destination instance id
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_send_opengauss_oldest_xmin(dms_context_t *dms_ctx, unsigned long long oldest_xmin,
    unsigned char dest_id);
    
DMS_DECLARE int dms_get_drc_info(int *is_found, dv_drc_buf_info* drc_info);

/*
 * @brief retrieve mes statistics of waiting events
 * @[in]param cmd - the type of mes waiting event
 * @[out]param event_cnt - the count of the happenings of specified waiting event
 * @[out]param event_time - the total cost time of specified waiting event
 * @return DMS_SUCCESS - success;otherwise: failed
 */   
DMS_DECLARE int dms_get_mes_wait_event(unsigned int cmd, unsigned long long *event_cnt, 
    unsigned long long *event_time);

DMS_DECLARE int dms_create_global_xa_res(dms_context_t *dms_ctx, unsigned char owner_id, unsigned char undo_set_id,
    unsigned int *remote_result, unsigned char ignore_exist);

DMS_DECLARE int dms_end_global_xa(dms_context_t *dms_ctx, unsigned long long flags, unsigned long long scn,
    unsigned char is_commit, int *remote_result);

DMS_DECLARE int dms_reform_rebuild_one_xa(dms_context_t *dms_ctx, unsigned char undo_set_id,
    unsigned char thread_index);

DMS_DECLARE void dms_get_cmd_stat(int cmd, wait_cmd_stat_result_t *cmd_stat_result);

DMS_DECLARE void dms_get_drc_local_lock_res(unsigned int *vmid, drc_local_lock_res_result_t *drc_local_lock_res_result);

DMS_DECLARE int dms_az_switchover_demote(unsigned int sess_id);
DMS_DECLARE int dms_az_switchover_promote(unsigned int sess_id);
DMS_DECLARE int dms_az_failover(unsigned int sess_id);

DMS_DECLARE void dms_reform_judgement_stat_fetch_prepare(unsigned int *curr_pos, unsigned int *curr_index);

DMS_DECLARE void dms_reform_judgement_stat_fetch(unsigned int curr_pos, unsigned int curr_index, unsigned int *eof,
    long long int *times, char *desc, int len);

DMS_DECLARE void dms_reset_error(void);

/*
 * @brief request primary node do checkpoint immediately, only for openGauss
 * @[in]param dms_ctx - context information.
 * @[out]ckpt_loc - primary checkpoint redo loc.
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_req_opengauss_immediate_ckpt(dms_context_t *dms_ctx, unsigned long long *ckpt_loc);

/*
 * @brief estimated total memory consumed by dms_init
 * @[in]param profile - config value
 * @[out]total memory consumed by dms_init
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_calc_mem_usage(dms_profile_t *dms_profile, unsigned long long *total_mem);

DMS_DECLARE void dms_reform_proc_callback_stat_start(reform_callback_stat_e callback_stat);
DMS_DECLARE void dms_reform_proc_callback_stat_end(reform_callback_stat_e callback_stat);
DMS_DECLARE void dms_reform_proc_callback_stat_times(reform_callback_stat_e callback_stat);

/*
 * @brief set dms fi entries from db params
 * @[in]param type - fault type
 * @[in]param entries - fault entries array
 * @[in]param count - the hwm of array
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_fi_set_entries(unsigned int type, unsigned int *entries, unsigned int count);

/*
 * @brief set dms fi value from db params
 * @[in]param type - fault type
 * @[in]param value - fault value
 * @return DMS_SUCCESS - success;otherwise: failed
 */
DMS_DECLARE int dms_fi_set_entry_value(unsigned int type, unsigned int value);
DMS_DECLARE int dms_reform_rebuild_send_rest(unsigned int sess_id, unsigned char thread_index);

/*
 * @brief get thread local storage var
 * @return var
 */
DMS_DECLARE int dms_fi_get_tls_trigger_custom();

/*
 * @brief set thread local storage var
 * @[in]param val - value
 */
DMS_DECLARE void dms_fi_set_tls_trigger_custom(int val);

DMS_DECLARE int dms_get_reform_locking(void);

/*
 * @brief call fault injection
 * @[in]param point - fault index
 */
DMS_DECLARE void fault_injection_call(unsigned int point, ...);

DMS_DECLARE void dms_lock_res_ctrl_shared_mode(unsigned int sid);

DMS_DECLARE void dms_unlock_res_ctrl();

#ifdef __cplusplus
}
#endif

#endif /* __DMS_H__ */

