﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace ICP.Modules.Api.Member.Models.MemberInfo
{
    using Infrastructure.Core.Models.Consts;
    using Library.Models.AuthorizationApi;

    public class CheckRegisterAuthSMSRequest: BaseOPAuthorizationApiRequest
    {
        [Required]
        [RegularExpression(RegexConst.CellPhone, ErrorMessage = "{0} 格式錯誤")]
        [Display(Name = "手機號碼")]
        public string CellPhone { get; set; }

        [Required]
        [Display(Name = "驗證碼")]
        public string AuthCode { get; set; }
    }
}
