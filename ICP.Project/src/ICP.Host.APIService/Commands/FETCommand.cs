﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ICP.Host.APIService.Commands
{
    using Infrastructure.Core.Models;
    using Models;
    using Services;

    public class FETCommand
    {
        FETService _fetService;

        public FETCommand(FETService fetService)
        {
            _fetService = fetService;
        }

        /// <summary>
        /// 取得待發送簡訊
        /// </summary>
        /// <param name="States"></param>
        /// <param name="ChangeStates"></param>
        /// <returns></returns>
        public List<FETTemp> ListFetTemp(byte States, byte ChangeStates)
        {
            return _fetService.ListFetTemp(States, ChangeStates);
        }

        /// <summary>
        /// 更新簡訊發送狀態
        /// </summary>
        /// <param name="AutoID"></param>
        /// <param name="RtnCode"></param>
        /// <param name="RtnMsg"></param>
        /// <param name="MessageId"></param>
        /// <returns></returns>
        public BaseResult UpdateReceiveSMS(long AutoID, string RtnCode, string RtnMsg, string MessageId)
        {
            return _fetService.UpdateReceiveSMS(AutoID, RtnCode, RtnMsg, MessageId);
        }

        /// <summary>
        /// 接收簡訊發送結果
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public BaseResult AddFETRtnInfo(FETRtnModel model)
        {
            return _fetService.AddFETRtnInfo(model);
        }
    }
}