﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.Library.Models.ManageBank.FirstBank
{
    /// <summary>
    /// 台幣單/多筆付款訊息內容
    /// </summary>
    public class B2B001
    {
        /// <summary>
        /// 筆數檢核值
        /// </summary>
        public int ChksumRecord { get; set; }

        /// <summary>
        /// 逐筆交易資料
        /// </summary>
        public class RecordModel
        {
            /// <summary>
            /// 資料流水序號
            /// </summary>
            public int RecordSeqNo { get; set; }

            /// <summary>
            /// 付款編號
            /// </summary>
            public string PmtRemitRefId { get; set; }

            /// <summary>
            /// 付款帳號所屬統一編號 ID
            /// </summary>
            public string PayAccountId { get; set; }

            /// <summary>
            /// 付款帳號戶名
            /// </summary>
            public string PayAccountName { get; set; }

            /// <summary>
            /// 付款帳號
            /// </summary>
            public string PayAccount { get; set; }

            /// <summary>
            /// 付款金額
            /// </summary>
            public int PayAmount { get; set; }

            /// <summary>
            /// 手續費分擔別
            /// </summary>
            public string ChargeRegulation { get; set; }

            /// <summary>
            /// 付款日
            /// </summary>
            public string PayDate { get; set; }

            /// <summary>
            /// 存摺摘要
            /// </summary>
            public string BankbookDigest { get; set; }

            /// <summary>
            /// 付款附言
            /// </summary>
            public string PayMemo { get; set; }

            /// <summary>
            /// 跨行途徑
            /// </summary>
            public string SettlePath { get; set; }

            /// <summary>
            /// 收款人資訊
            /// </summary>
            public PayeeInfoModel PayeeInfo { get; set; }

            /// <summary>
            /// 通知內容
            /// </summary>
            public NoticeModel Notice { get; set; }

            /// <summary>
            /// 匯款內容明細
            /// </summary>
            public List<BillInfoModel> RemitDetail { get; set; }
        }

        /// <summary>
        /// 逐筆交易資料
        /// </summary>
        [System.Xml.Serialization.XmlElement]
        public List<RecordModel> Record { get; set; }
    }
}