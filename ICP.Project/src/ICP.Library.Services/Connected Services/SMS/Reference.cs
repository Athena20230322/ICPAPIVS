﻿//------------------------------------------------------------------------------
// <auto-generated>
//     這段程式碼是由工具產生的。
//     執行階段版本:4.0.30319.42000
//
//     對這個檔案所做的變更可能會造成錯誤的行為，而且如果重新產生程式碼，
//     變更將會遺失。
// </auto-generated>
//------------------------------------------------------------------------------

namespace ICP.Library.Services.SMS {
    using System.Runtime.Serialization;
    using System;
    
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Runtime.Serialization", "4.0.0.0")]
    [System.Runtime.Serialization.DataContractAttribute(Name="BaseResult", Namespace="http://tempuri.org/")]
    [System.SerializableAttribute()]
    public partial class BaseResult : object, System.Runtime.Serialization.IExtensibleDataObject, System.ComponentModel.INotifyPropertyChanged {
        
        [System.NonSerializedAttribute()]
        private System.Runtime.Serialization.ExtensionDataObject extensionDataField;
        
        private bool IsSuccessField;
        
        private int RtnCodeField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string RtnMsgField;
        
        [global::System.ComponentModel.BrowsableAttribute(false)]
        public System.Runtime.Serialization.ExtensionDataObject ExtensionData {
            get {
                return this.extensionDataField;
            }
            set {
                this.extensionDataField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public bool IsSuccess {
            get {
                return this.IsSuccessField;
            }
            set {
                if ((this.IsSuccessField.Equals(value) != true)) {
                    this.IsSuccessField = value;
                    this.RaisePropertyChanged("IsSuccess");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true)]
        public int RtnCode {
            get {
                return this.RtnCodeField;
            }
            set {
                if ((this.RtnCodeField.Equals(value) != true)) {
                    this.RtnCodeField = value;
                    this.RaisePropertyChanged("RtnCode");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false)]
        public string RtnMsg {
            get {
                return this.RtnMsgField;
            }
            set {
                if ((object.ReferenceEquals(this.RtnMsgField, value) != true)) {
                    this.RtnMsgField = value;
                    this.RaisePropertyChanged("RtnMsg");
                }
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Runtime.Serialization", "4.0.0.0")]
    [System.Runtime.Serialization.DataContractAttribute(Name="FETRtnModel", Namespace="http://tempuri.org/")]
    [System.SerializableAttribute()]
    public partial class FETRtnModel : object, System.Runtime.Serialization.IExtensibleDataObject, System.ComponentModel.INotifyPropertyChanged {
        
        [System.NonSerializedAttribute()]
        private System.Runtime.Serialization.ExtensionDataObject extensionDataField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string SysIdField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string MessageIdField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string DestAddressField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string DeliveryStatusField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string ErrorCodeField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string SubmitDateField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string DoneDateField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string SeqField;
        
        [global::System.ComponentModel.BrowsableAttribute(false)]
        public System.Runtime.Serialization.ExtensionDataObject ExtensionData {
            get {
                return this.extensionDataField;
            }
            set {
                this.extensionDataField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false)]
        public string SysId {
            get {
                return this.SysIdField;
            }
            set {
                if ((object.ReferenceEquals(this.SysIdField, value) != true)) {
                    this.SysIdField = value;
                    this.RaisePropertyChanged("SysId");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=1)]
        public string MessageId {
            get {
                return this.MessageIdField;
            }
            set {
                if ((object.ReferenceEquals(this.MessageIdField, value) != true)) {
                    this.MessageIdField = value;
                    this.RaisePropertyChanged("MessageId");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=2)]
        public string DestAddress {
            get {
                return this.DestAddressField;
            }
            set {
                if ((object.ReferenceEquals(this.DestAddressField, value) != true)) {
                    this.DestAddressField = value;
                    this.RaisePropertyChanged("DestAddress");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=3)]
        public string DeliveryStatus {
            get {
                return this.DeliveryStatusField;
            }
            set {
                if ((object.ReferenceEquals(this.DeliveryStatusField, value) != true)) {
                    this.DeliveryStatusField = value;
                    this.RaisePropertyChanged("DeliveryStatus");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=4)]
        public string ErrorCode {
            get {
                return this.ErrorCodeField;
            }
            set {
                if ((object.ReferenceEquals(this.ErrorCodeField, value) != true)) {
                    this.ErrorCodeField = value;
                    this.RaisePropertyChanged("ErrorCode");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=5)]
        public string SubmitDate {
            get {
                return this.SubmitDateField;
            }
            set {
                if ((object.ReferenceEquals(this.SubmitDateField, value) != true)) {
                    this.SubmitDateField = value;
                    this.RaisePropertyChanged("SubmitDate");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=6)]
        public string DoneDate {
            get {
                return this.DoneDateField;
            }
            set {
                if ((object.ReferenceEquals(this.DoneDateField, value) != true)) {
                    this.DoneDateField = value;
                    this.RaisePropertyChanged("DoneDate");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=7)]
        public string Seq {
            get {
                return this.SeqField;
            }
            set {
                if ((object.ReferenceEquals(this.SeqField, value) != true)) {
                    this.SeqField = value;
                    this.RaisePropertyChanged("Seq");
                }
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.Runtime.Serialization", "4.0.0.0")]
    [System.Runtime.Serialization.DataContractAttribute(Name="MistakeRtnModel", Namespace="http://tempuri.org/")]
    [System.SerializableAttribute()]
    public partial class MistakeRtnModel : object, System.Runtime.Serialization.IExtensibleDataObject, System.ComponentModel.INotifyPropertyChanged {
        
        [System.NonSerializedAttribute()]
        private System.Runtime.Serialization.ExtensionDataObject extensionDataField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string MessageIdField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string DstAddrField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string DlvtimeField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string DoneTimeField;
        
        private int StatusCodeField;
        
        [System.Runtime.Serialization.OptionalFieldAttribute()]
        private string StatusStrField;
        
        private int StatusFlagField;
        
        [global::System.ComponentModel.BrowsableAttribute(false)]
        public System.Runtime.Serialization.ExtensionDataObject ExtensionData {
            get {
                return this.extensionDataField;
            }
            set {
                this.extensionDataField = value;
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false)]
        public string MessageId {
            get {
                return this.MessageIdField;
            }
            set {
                if ((object.ReferenceEquals(this.MessageIdField, value) != true)) {
                    this.MessageIdField = value;
                    this.RaisePropertyChanged("MessageId");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=1)]
        public string DstAddr {
            get {
                return this.DstAddrField;
            }
            set {
                if ((object.ReferenceEquals(this.DstAddrField, value) != true)) {
                    this.DstAddrField = value;
                    this.RaisePropertyChanged("DstAddr");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=2)]
        public string Dlvtime {
            get {
                return this.DlvtimeField;
            }
            set {
                if ((object.ReferenceEquals(this.DlvtimeField, value) != true)) {
                    this.DlvtimeField = value;
                    this.RaisePropertyChanged("Dlvtime");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=3)]
        public string DoneTime {
            get {
                return this.DoneTimeField;
            }
            set {
                if ((object.ReferenceEquals(this.DoneTimeField, value) != true)) {
                    this.DoneTimeField = value;
                    this.RaisePropertyChanged("DoneTime");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true, Order=4)]
        public int StatusCode {
            get {
                return this.StatusCodeField;
            }
            set {
                if ((this.StatusCodeField.Equals(value) != true)) {
                    this.StatusCodeField = value;
                    this.RaisePropertyChanged("StatusCode");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=5)]
        public string StatusStr {
            get {
                return this.StatusStrField;
            }
            set {
                if ((object.ReferenceEquals(this.StatusStrField, value) != true)) {
                    this.StatusStrField = value;
                    this.RaisePropertyChanged("StatusStr");
                }
            }
        }
        
        [System.Runtime.Serialization.DataMemberAttribute(IsRequired=true, Order=6)]
        public int StatusFlag {
            get {
                return this.StatusFlagField;
            }
            set {
                if ((this.StatusFlagField.Equals(value) != true)) {
                    this.StatusFlagField = value;
                    this.RaisePropertyChanged("StatusFlag");
                }
            }
        }
        
        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;
        
        protected void RaisePropertyChanged(string propertyName) {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null)) {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ServiceModel.ServiceContractAttribute(ConfigurationName="SMS.SMSSoap")]
    public interface SMSSoap {
        
        // CODEGEN: 命名空間 http://tempuri.org/ 的元素名稱  Phone 未標示為 nillable，正在產生訊息合約
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/SendSMS", ReplyAction="*")]
        ICP.Library.Services.SMS.SendSMSResponse SendSMS(ICP.Library.Services.SMS.SendSMSRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/SendSMS", ReplyAction="*")]
        System.Threading.Tasks.Task<ICP.Library.Services.SMS.SendSMSResponse> SendSMSAsync(ICP.Library.Services.SMS.SendSMSRequest request);
        
        // CODEGEN: 命名空間 http://tempuri.org/ 的元素名稱  model 未標示為 nillable，正在產生訊息合約
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/AddFETRtnInfo", ReplyAction="*")]
        ICP.Library.Services.SMS.AddFETRtnInfoResponse AddFETRtnInfo(ICP.Library.Services.SMS.AddFETRtnInfoRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/AddFETRtnInfo", ReplyAction="*")]
        System.Threading.Tasks.Task<ICP.Library.Services.SMS.AddFETRtnInfoResponse> AddFETRtnInfoAsync(ICP.Library.Services.SMS.AddFETRtnInfoRequest request);
        
        // CODEGEN: 命名空間 http://tempuri.org/ 的元素名稱  model 未標示為 nillable，正在產生訊息合約
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/AddMistakeInfo", ReplyAction="*")]
        ICP.Library.Services.SMS.AddMistakeInfoResponse AddMistakeInfo(ICP.Library.Services.SMS.AddMistakeInfoRequest request);
        
        [System.ServiceModel.OperationContractAttribute(Action="http://tempuri.org/AddMistakeInfo", ReplyAction="*")]
        System.Threading.Tasks.Task<ICP.Library.Services.SMS.AddMistakeInfoResponse> AddMistakeInfoAsync(ICP.Library.Services.SMS.AddMistakeInfoRequest request);
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class SendSMSRequest {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="SendSMS", Namespace="http://tempuri.org/", Order=0)]
        public ICP.Library.Services.SMS.SendSMSRequestBody Body;
        
        public SendSMSRequest() {
        }
        
        public SendSMSRequest(ICP.Library.Services.SMS.SendSMSRequestBody Body) {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://tempuri.org/")]
    public partial class SendSMSRequestBody {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public string Phone;
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=1)]
        public string MsgData;
        
        [System.Runtime.Serialization.DataMemberAttribute(Order=2)]
        public byte SMSType;
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=3)]
        public string Sender;
        
        public SendSMSRequestBody() {
        }
        
        public SendSMSRequestBody(string Phone, string MsgData, byte SMSType, string Sender) {
            this.Phone = Phone;
            this.MsgData = MsgData;
            this.SMSType = SMSType;
            this.Sender = Sender;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class SendSMSResponse {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="SendSMSResponse", Namespace="http://tempuri.org/", Order=0)]
        public ICP.Library.Services.SMS.SendSMSResponseBody Body;
        
        public SendSMSResponse() {
        }
        
        public SendSMSResponse(ICP.Library.Services.SMS.SendSMSResponseBody Body) {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://tempuri.org/")]
    public partial class SendSMSResponseBody {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public ICP.Library.Services.SMS.BaseResult SendSMSResult;
        
        public SendSMSResponseBody() {
        }
        
        public SendSMSResponseBody(ICP.Library.Services.SMS.BaseResult SendSMSResult) {
            this.SendSMSResult = SendSMSResult;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class AddFETRtnInfoRequest {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="AddFETRtnInfo", Namespace="http://tempuri.org/", Order=0)]
        public ICP.Library.Services.SMS.AddFETRtnInfoRequestBody Body;
        
        public AddFETRtnInfoRequest() {
        }
        
        public AddFETRtnInfoRequest(ICP.Library.Services.SMS.AddFETRtnInfoRequestBody Body) {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://tempuri.org/")]
    public partial class AddFETRtnInfoRequestBody {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public ICP.Library.Services.SMS.FETRtnModel model;
        
        public AddFETRtnInfoRequestBody() {
        }
        
        public AddFETRtnInfoRequestBody(ICP.Library.Services.SMS.FETRtnModel model) {
            this.model = model;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class AddFETRtnInfoResponse {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="AddFETRtnInfoResponse", Namespace="http://tempuri.org/", Order=0)]
        public ICP.Library.Services.SMS.AddFETRtnInfoResponseBody Body;
        
        public AddFETRtnInfoResponse() {
        }
        
        public AddFETRtnInfoResponse(ICP.Library.Services.SMS.AddFETRtnInfoResponseBody Body) {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://tempuri.org/")]
    public partial class AddFETRtnInfoResponseBody {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public ICP.Library.Services.SMS.BaseResult AddFETRtnInfoResult;
        
        public AddFETRtnInfoResponseBody() {
        }
        
        public AddFETRtnInfoResponseBody(ICP.Library.Services.SMS.BaseResult AddFETRtnInfoResult) {
            this.AddFETRtnInfoResult = AddFETRtnInfoResult;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class AddMistakeInfoRequest {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="AddMistakeInfo", Namespace="http://tempuri.org/", Order=0)]
        public ICP.Library.Services.SMS.AddMistakeInfoRequestBody Body;
        
        public AddMistakeInfoRequest() {
        }
        
        public AddMistakeInfoRequest(ICP.Library.Services.SMS.AddMistakeInfoRequestBody Body) {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://tempuri.org/")]
    public partial class AddMistakeInfoRequestBody {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public ICP.Library.Services.SMS.MistakeRtnModel model;
        
        public AddMistakeInfoRequestBody() {
        }
        
        public AddMistakeInfoRequestBody(ICP.Library.Services.SMS.MistakeRtnModel model) {
            this.model = model;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped=false)]
    public partial class AddMistakeInfoResponse {
        
        [System.ServiceModel.MessageBodyMemberAttribute(Name="AddMistakeInfoResponse", Namespace="http://tempuri.org/", Order=0)]
        public ICP.Library.Services.SMS.AddMistakeInfoResponseBody Body;
        
        public AddMistakeInfoResponse() {
        }
        
        public AddMistakeInfoResponse(ICP.Library.Services.SMS.AddMistakeInfoResponseBody Body) {
            this.Body = Body;
        }
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.Runtime.Serialization.DataContractAttribute(Namespace="http://tempuri.org/")]
    public partial class AddMistakeInfoResponseBody {
        
        [System.Runtime.Serialization.DataMemberAttribute(EmitDefaultValue=false, Order=0)]
        public ICP.Library.Services.SMS.BaseResult AddMistakeInfoResult;
        
        public AddMistakeInfoResponseBody() {
        }
        
        public AddMistakeInfoResponseBody(ICP.Library.Services.SMS.BaseResult AddMistakeInfoResult) {
            this.AddMistakeInfoResult = AddMistakeInfoResult;
        }
    }
    
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public interface SMSSoapChannel : ICP.Library.Services.SMS.SMSSoap, System.ServiceModel.IClientChannel {
    }
    
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.CodeDom.Compiler.GeneratedCodeAttribute("System.ServiceModel", "4.0.0.0")]
    public partial class SMSSoapClient : System.ServiceModel.ClientBase<ICP.Library.Services.SMS.SMSSoap>, ICP.Library.Services.SMS.SMSSoap {
        
        public SMSSoapClient() {
        }
        
        public SMSSoapClient(string endpointConfigurationName) : 
                base(endpointConfigurationName) {
        }
        
        public SMSSoapClient(string endpointConfigurationName, string remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public SMSSoapClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(endpointConfigurationName, remoteAddress) {
        }
        
        public SMSSoapClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) : 
                base(binding, remoteAddress) {
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        ICP.Library.Services.SMS.SendSMSResponse ICP.Library.Services.SMS.SMSSoap.SendSMS(ICP.Library.Services.SMS.SendSMSRequest request) {
            return base.Channel.SendSMS(request);
        }
        
        public ICP.Library.Services.SMS.BaseResult SendSMS(string Phone, string MsgData, byte SMSType, string Sender) {
            ICP.Library.Services.SMS.SendSMSRequest inValue = new ICP.Library.Services.SMS.SendSMSRequest();
            inValue.Body = new ICP.Library.Services.SMS.SendSMSRequestBody();
            inValue.Body.Phone = Phone;
            inValue.Body.MsgData = MsgData;
            inValue.Body.SMSType = SMSType;
            inValue.Body.Sender = Sender;
            ICP.Library.Services.SMS.SendSMSResponse retVal = ((ICP.Library.Services.SMS.SMSSoap)(this)).SendSMS(inValue);
            return retVal.Body.SendSMSResult;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<ICP.Library.Services.SMS.SendSMSResponse> ICP.Library.Services.SMS.SMSSoap.SendSMSAsync(ICP.Library.Services.SMS.SendSMSRequest request) {
            return base.Channel.SendSMSAsync(request);
        }
        
        public System.Threading.Tasks.Task<ICP.Library.Services.SMS.SendSMSResponse> SendSMSAsync(string Phone, string MsgData, byte SMSType, string Sender) {
            ICP.Library.Services.SMS.SendSMSRequest inValue = new ICP.Library.Services.SMS.SendSMSRequest();
            inValue.Body = new ICP.Library.Services.SMS.SendSMSRequestBody();
            inValue.Body.Phone = Phone;
            inValue.Body.MsgData = MsgData;
            inValue.Body.SMSType = SMSType;
            inValue.Body.Sender = Sender;
            return ((ICP.Library.Services.SMS.SMSSoap)(this)).SendSMSAsync(inValue);
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        ICP.Library.Services.SMS.AddFETRtnInfoResponse ICP.Library.Services.SMS.SMSSoap.AddFETRtnInfo(ICP.Library.Services.SMS.AddFETRtnInfoRequest request) {
            return base.Channel.AddFETRtnInfo(request);
        }
        
        public ICP.Library.Services.SMS.BaseResult AddFETRtnInfo(ICP.Library.Services.SMS.FETRtnModel model) {
            ICP.Library.Services.SMS.AddFETRtnInfoRequest inValue = new ICP.Library.Services.SMS.AddFETRtnInfoRequest();
            inValue.Body = new ICP.Library.Services.SMS.AddFETRtnInfoRequestBody();
            inValue.Body.model = model;
            ICP.Library.Services.SMS.AddFETRtnInfoResponse retVal = ((ICP.Library.Services.SMS.SMSSoap)(this)).AddFETRtnInfo(inValue);
            return retVal.Body.AddFETRtnInfoResult;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<ICP.Library.Services.SMS.AddFETRtnInfoResponse> ICP.Library.Services.SMS.SMSSoap.AddFETRtnInfoAsync(ICP.Library.Services.SMS.AddFETRtnInfoRequest request) {
            return base.Channel.AddFETRtnInfoAsync(request);
        }
        
        public System.Threading.Tasks.Task<ICP.Library.Services.SMS.AddFETRtnInfoResponse> AddFETRtnInfoAsync(ICP.Library.Services.SMS.FETRtnModel model) {
            ICP.Library.Services.SMS.AddFETRtnInfoRequest inValue = new ICP.Library.Services.SMS.AddFETRtnInfoRequest();
            inValue.Body = new ICP.Library.Services.SMS.AddFETRtnInfoRequestBody();
            inValue.Body.model = model;
            return ((ICP.Library.Services.SMS.SMSSoap)(this)).AddFETRtnInfoAsync(inValue);
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        ICP.Library.Services.SMS.AddMistakeInfoResponse ICP.Library.Services.SMS.SMSSoap.AddMistakeInfo(ICP.Library.Services.SMS.AddMistakeInfoRequest request) {
            return base.Channel.AddMistakeInfo(request);
        }
        
        public ICP.Library.Services.SMS.BaseResult AddMistakeInfo(ICP.Library.Services.SMS.MistakeRtnModel model) {
            ICP.Library.Services.SMS.AddMistakeInfoRequest inValue = new ICP.Library.Services.SMS.AddMistakeInfoRequest();
            inValue.Body = new ICP.Library.Services.SMS.AddMistakeInfoRequestBody();
            inValue.Body.model = model;
            ICP.Library.Services.SMS.AddMistakeInfoResponse retVal = ((ICP.Library.Services.SMS.SMSSoap)(this)).AddMistakeInfo(inValue);
            return retVal.Body.AddMistakeInfoResult;
        }
        
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        System.Threading.Tasks.Task<ICP.Library.Services.SMS.AddMistakeInfoResponse> ICP.Library.Services.SMS.SMSSoap.AddMistakeInfoAsync(ICP.Library.Services.SMS.AddMistakeInfoRequest request) {
            return base.Channel.AddMistakeInfoAsync(request);
        }
        
        public System.Threading.Tasks.Task<ICP.Library.Services.SMS.AddMistakeInfoResponse> AddMistakeInfoAsync(ICP.Library.Services.SMS.MistakeRtnModel model) {
            ICP.Library.Services.SMS.AddMistakeInfoRequest inValue = new ICP.Library.Services.SMS.AddMistakeInfoRequest();
            inValue.Body = new ICP.Library.Services.SMS.AddMistakeInfoRequestBody();
            inValue.Body.model = model;
            return ((ICP.Library.Services.SMS.SMSSoap)(this)).AddMistakeInfoAsync(inValue);
        }
    }
}
