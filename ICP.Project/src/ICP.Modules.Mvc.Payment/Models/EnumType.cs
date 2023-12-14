﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ICP.Modules.Mvc.Payment.Models.Payment
{
    public enum eTradeType
    {
        EC = 1,
        Mobile = 2
    }

    public enum ePaymentType
    {
        TRANSACTION_ICASH = 1,
        ACCOUNTLINK = 2,        
        ATM = 3,
        CASH = 4,
        INVOICE = 5,
        TRANSFER_ICASH = 6,
        WITHDRAWAL_ICASH = 7,
        ADJUST_ICASH = 8,
        ALLOCATE_ICASH = 9
    }

    public enum eTradeMode
    {
        Transaction = 1,    //交易
        Topup = 2,          //儲值
        Transfer = 3,       //轉帳
        Withdrawal = 4,     //提領
        Refund = 5,         //退款  
    }
}
