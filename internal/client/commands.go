// Copyright (C) 2026 Neutrino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package client

import (
	"sort"

	"neutrino/internal/i18n"
)

// CmdID is a TUI slash command's canonical identifier. The command name
// recognized by the parser is always in English (e.g. "/invite"),
// regardless of the interface's active language — only the argument and
// description stay localized (see i18n.SetActive).
type CmdID = i18n.CmdID

const (
	// cmdNone is the zero value: no command resolved/no choice made yet
	// (used as the default for fields like model.contactPickerCmd before first use).
	cmdNone CmdID = iota
	CmdHelp
	CmdAddContact
	CmdActive
	CmdBackup
	CmdDelContact
	CmdDebug
	CmdCompact
	CmdConsoleExport
	CmdDelGroup
	CmdEdit
	CmdJoin
	CmdClose
	CmdSave
	CmdHealth
	CmdIgnore
	CmdSendContact
	CmdInfo
	CmdRoomInfo
	CmdInvite
	CmdNukex
	CmdPasswd
	CmdDuress
	CmdPing
	CmdQuit
	CmdReconnect
	CmdReinvite
	CmdAddMember
	CmdRecall
	CmdSafety
	CmdVerifySafety
	CmdSaveGroup
	CmdSendFile
	CmdShowQR
	CmdReadQR
	CmdInfoApp
	CmdBan
	CmdRemoteNuke
	CmdIndoorSync
	CmdDevices
	CmdDeviceLabel
	CmdMsgAcks
	CmdPQCSign
	CmdPromote
	CmdRotateRelIdentity
	CmdRotateRelContent
	CmdRotateKey
	CmdDeviceSync
	CmdLock
	CmdLockPIN
	CmdLockTimeout
	CmdNukeTimeout
	CmdMsg
	CmdClearAll
	CmdUnverifySafety
)

// cmdDef describes a command: name (with slash, always English), and
// the i18n catalog keys for the argument placeholder and the
// help/palette description — resolved in the active language by
// i18n.T().
type cmdDef struct {
	id              CmdID
	name            string
	argKey, descKey string
}

var commandDefs = []cmdDef{
	{CmdHelp, "/help", "tui.help_help_arg", "tui.help_help_desc"},
	{CmdAddContact, "/cnt-add", "tui.help_cnt_add_arg", "tui.help_cnt_add_desc"},
	{CmdActive, "/active", "tui.help_active_arg", "tui.help_active_desc"},
	{CmdBackup, "/sec-backup", "tui.help_sec_backup_arg", "tui.help_sec_backup_desc"},
	{CmdDelContact, "/cnt-del", "tui.help_cnt_del_arg", "tui.help_cnt_del_desc"},
	{CmdDebug, "/debug", "tui.help_debug_arg", "tui.help_debug_desc"},
	{CmdCompact, "/compact", "tui.help_compact_arg", "tui.help_compact_desc"},
	{CmdConsoleExport, "/console-export", "tui.help_console_export_arg", "tui.help_console_export_desc"},
	{CmdDelGroup, "/grp-del", "tui.help_grp_del_arg", "tui.help_grp_del_desc"},
	{CmdEdit, "/cnt-edit", "tui.help_cnt_edit_arg", "tui.help_cnt_edit_desc"},
	{CmdJoin, "/grp-join", "tui.help_grp_join_arg", "tui.help_grp_join_desc"},
	{CmdClose, "/grp-exit", "tui.help_grp_exit_arg", "tui.help_grp_exit_desc"},
	{CmdSave, "/cnt-save", "tui.help_cnt_save_arg", "tui.help_cnt_save_desc"},
	{CmdHealth, "/grp-health", "tui.help_grp_health_arg", "tui.help_grp_health_desc"},
	{CmdIgnore, "/cnt-ignore", "tui.help_cnt_ignore_arg", "tui.help_cnt_ignore_desc"},
	{CmdSendContact, "/grp-contact-send", "tui.help_grp_contact_send_arg", "tui.help_grp_contact_send_desc"},
	{CmdInfo, "/cnt-info", "tui.help_cnt_info_arg", "tui.help_cnt_info_desc"},
	{CmdRoomInfo, "/grp-info", "tui.help_grp_info_arg", "tui.help_grp_info_desc"},
	{CmdInvite, "/grp-invite", "tui.help_grp_invite_arg", "tui.help_grp_invite_desc"},
	{CmdNukex, "/nukex", "tui.help_nukex_arg", "tui.help_nukex_desc"},
	{CmdPasswd, "/sec-passwd", "tui.help_sec_passwd_arg", "tui.help_sec_passwd_desc"},
	{CmdDuress, "/sec-duress", "tui.help_sec_duress_arg", "tui.help_sec_duress_desc"},
	{CmdPing, "/grp-ping", "tui.help_grp_ping_arg", "tui.help_grp_ping_desc"},
	{CmdQuit, "/quit", "tui.help_quit_arg", "tui.help_quit_desc"},
	{CmdReconnect, "/grp-reconnect", "tui.help_grp_reconnect_arg", "tui.help_grp_reconnect_desc"},
	{CmdReinvite, "/grp-reinvite", "tui.help_grp_reinvite_arg", "tui.help_grp_reinvite_desc"},
	{CmdAddMember, "/grp-add-member", "tui.help_grp_add_member_arg", "tui.help_grp_add_member_desc"},
	{CmdRecall, "/grp-recall", "tui.help_grp_recall_arg", "tui.help_grp_recall_desc"},
	{CmdSafety, "/sec-safety", "tui.help_sec_safety_arg", "tui.help_sec_safety_desc"},
	{CmdVerifySafety, "/sec-verify", "tui.help_sec_verify_arg", "tui.help_sec_verify_desc"},
	{CmdUnverifySafety, "/sec-unverify", "tui.help_sec_unverify_arg", "tui.help_sec_unverify_desc"},
	{CmdSaveGroup, "/grp-save", "tui.help_grp_save_arg", "tui.help_grp_save_desc"},
	{CmdSendFile, "/grp-file-send", "tui.help_grp_file_send_arg", "tui.help_grp_file_send_desc"},
	{CmdShowQR, "/show-qr", "tui.help_show_qr_arg", "tui.help_show_qr_desc"},
	{CmdReadQR, "/cnt-read-qrcode", "tui.help_cnt_read_qrcode_arg", "tui.help_cnt_read_qrcode_desc"},
	{CmdInfoApp, "/info-app", "tui.help_info_app_arg", "tui.help_info_app_desc"},
	{CmdBan, "/grp-ban", "tui.help_grp_ban_arg", "tui.help_grp_ban_desc"},
	{CmdRemoteNuke, "/sec-remote-nuke", "tui.help_sec_remote_nuke_arg", "tui.help_sec_remote_nuke_desc"},
	{CmdIndoorSync, "/sec-indoor-sync", "tui.help_sec_indoor_sync_arg", "tui.help_sec_indoor_sync_desc"},
	{CmdDevices, "/sec-devices", "tui.help_sec_devices_arg", "tui.help_sec_devices_desc"},
	{CmdDeviceLabel, "/sec-device-label", "tui.help_sec_device_label_arg", "tui.help_sec_device_label_desc"},
	{CmdMsgAcks, "/grp-msg-acks", "tui.help_grp_msg_acks_arg", "tui.help_grp_msg_acks_desc"},
	{CmdPQCSign, "/sec-pqc-sign", "tui.help_sec_pqc_sign_arg", "tui.help_sec_pqc_sign_desc"},
	{CmdPromote, "/grp-promote", "tui.help_grp_promote_arg", "tui.help_grp_promote_desc"},
	{CmdRotateRelIdentity, "/sec-rotate-rel-identity", "tui.help_sec_rotate_rel_identity_arg", "tui.help_sec_rotate_rel_identity_desc"},
	{CmdRotateRelContent, "/sec-rotate-rel-content", "tui.help_sec_rotate_rel_content_arg", "tui.help_sec_rotate_rel_content_desc"},
	{CmdRotateKey, "/sec-rotate-key", "tui.help_sec_rotate_key_arg", "tui.help_sec_rotate_key_desc"},
	{CmdDeviceSync, "/sec-device-sync", "tui.help_sec_device_sync_arg", "tui.help_sec_device_sync_desc"},
	{CmdLock, "/sec-lock", "tui.help_sec_lock_arg", "tui.help_sec_lock_desc"},
	{CmdLockPIN, "/sec-lock-pin", "tui.help_sec_lock_pin_arg", "tui.help_sec_lock_pin_desc"},
	{CmdLockTimeout, "/sec-lock-timeout", "tui.help_sec_lock_timeout_arg", "tui.help_sec_lock_timeout_desc"},
	{CmdNukeTimeout, "/sec-nuke-timeout", "tui.help_sec_nuke_timeout_arg", "tui.help_sec_nuke_timeout_desc"},
	{CmdClearAll, "/sec-clear-all", "tui.help_sec_clear_all_arg", "tui.help_sec_clear_all_desc"},
	{CmdMsg, "/msg", "tui.help_msg_arg", "tui.help_msg_desc"},
}

// PaletteItem is a command resolved for the active language — name,
// argument and description. The single source of truth for the command
// table, shared by every user interface (the tui package's palette and
// /help).
type PaletteItem struct {
	ID   CmdID
	Cmd  string
	Arg  string
	Desc string
}

func init() {
	names := make(map[CmdID]string, len(commandDefs))
	for _, d := range commandDefs {
		names[d.id] = d.name
	}
	i18n.RegisterCommands(names)
}

// CommandList builds the command table (name, argument, description):
// name always in English, argument/description in the active language.
// /help always first, the rest in alphabetical order by name. Used by
// the TUI's palette and /help (tui package).
func CommandList() []PaletteItem {
	out := make([]PaletteItem, 0, len(commandDefs))
	for _, d := range commandDefs {
		out = append(out, PaletteItem{ID: d.id, Cmd: d.name, Arg: i18n.T(d.argKey), Desc: i18n.T(d.descKey)})
	}
	helpName := i18n.CommandName(CmdHelp)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cmd == helpName {
			return true
		}
		if out[j].Cmd == helpName {
			return false
		}
		return out[i].Cmd < out[j].Cmd
	})
	return out
}
