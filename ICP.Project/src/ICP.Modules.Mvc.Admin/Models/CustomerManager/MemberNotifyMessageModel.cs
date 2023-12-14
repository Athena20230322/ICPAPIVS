﻿using AutoMapper;
using ICP.Infrastructure.Core.Models;
using ICP.Library.Models.MemberModels;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.Modules.Mvc.Admin.Models.CustomerManager
{
    using System;
    using System.Collections.Generic;
    public class MemberNotifyMessageModel : BaseListModel
    {
        /// <summary>
        /// 會員編號
        /// </summary>
        public long MID { get; set; }

        /// <summary>
        /// 通知訊息編號
        /// </summary>
        public long NotifyMessageID { get; set; }

        /// <summary>
        /// 類別編號
        /// </summary>
        public long CategoryID { get; set; }

        /// <summary>
        /// 是否讀取 0: 預設值, 1: 已讀取
        /// </summary>
        public byte isRead { get; set; }

        /// <summary>
        /// 狀態 0: 已刪除, 1: 正常
        /// </summary>
        public byte Status { get; set; }

        /// <summary>
        /// 建立日期
        /// </summary>
        public DateTime CreateDate { get; set; }

        /// <summary>
        /// 主旨
        /// </summary>
        public string Subject { get; set; }

        /// <summary>
        /// 類別名稱
        /// </summary>
        public string CategoryName { get; set; }

    }


}
